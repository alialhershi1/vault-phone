"""Vault Leech: authorized YouTube and Instagram video downloader.

The engine owns extraction, queue processing and retries. The host
application supplies authentication and the encrypted Discord-vault storage
callback; downloader cookies are optional and never include vault credentials.
"""
import os, re, time, random, tempfile, threading, shutil, subprocess, json
from urllib.parse import urlparse, parse_qs
from flask import abort, jsonify, request
import leech_queue as Q

MAX_BYTES = 500 * 1024 * 1024
MAX_ATTEMPTS = 5
BATCH_MAX = 1000
YT_HOSTS = {"youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be"}
IG_HOSTS = {"instagram.com", "www.instagram.com", "m.instagram.com"}
_THROTTLE = (
    "empty media response", "rate-limit", "rate limit", "429", "too many requests",
    "not granting access", "failed to parse json", "jsondecodeerror",
    "failed to extract any player response"
)
_PERMANENT = (
    "private", "login required", "unavailable", "removed", "does not exist",
    "not found", "404", "age-restricted", "exceeds the 500"
)
_WAKE = threading.Event()
_COOL = {"until": 0.0}
_STARTED = False
_LOCK = threading.Lock()


def valid_url(raw):
    """Allow only supported public video URL patterns; normalize to one video."""
    try:
        p = urlparse(str(raw).strip())
        host = (p.hostname or "").lower().rstrip(".")
        if p.scheme not in ("http", "https") or p.username or p.password:
            return None
        if host in IG_HOSTS:
            m = re.match(r"^/(?:[^/]+/)?(?:reel|reels)/([A-Za-z0-9_-]+)", p.path)
            return "https://www.instagram.com/reel/" + m.group(1) + "/" if m else None
        if host not in YT_HOSTS:
            return None
        video_id = ""
        if host == "youtu.be":
            video_id = p.path.strip("/").split("/")[0]
        elif p.path.rstrip("/") == "/watch":
            video_id = (parse_qs(p.query).get("v") or [""])[0]
        else:
            m = re.match(r"^/(?:shorts|live|embed|v)/([A-Za-z0-9_-]{11})(?:/|$)", p.path)
            video_id = m.group(1) if m else ""
        if not re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id):
            return None
        return "https://www.youtube.com/watch?v=" + video_id
    except Exception:
        return None


def _platform(url):
    host = (urlparse(url).hostname or "").lower()
    return "youtube" if host in YT_HOSTS else "instagram"


def _cookie_file(temp_dir, platform):
    """Write a private Netscape cookie jar from a Netscape export or Cookie header.

    Cookie values are credentials: never log, return, or include them in errors.
    """
    names = ("YT_COOKIES", "YOUTUBE_COOKIES") if platform == "youtube" else ("IG_COOKIES",)
    raw = next((os.environ.get(name, "").strip() for name in names if os.environ.get(name, "").strip()), "")
    if not raw:
        return None

    raw = raw.replace("\r\n", "\n").replace("\r", "\n").strip()
    lines = raw.splitlines()
    cookie_rows = [line for line in lines if line and not line.lstrip().startswith("#")]
    is_netscape = bool(cookie_rows) and all(len(line.split("\t")) >= 7 for line in cookie_rows)

    if is_netscape:
        text = raw.rstrip() + "\n"
        count = len(cookie_rows)
    else:
        header = re.sub(r"(?im)^\s*cookie\s*:\s*", "", raw).replace("\n", ";")
        domain = ".youtube.com" if platform == "youtube" else ".instagram.com"
        rows = []
        for part in header.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name, value = name.strip(), value.strip()
            if not value or not re.fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]+", name):
                continue
            rows.append("%s\tTRUE\t/\tTRUE\t0\t%s\t%s" % (domain, name, value))
        if not rows:
            raise RuntimeError("Configured video cookies are empty or invalid. Set YT_COOKIES to a Netscape cookies.txt export or Cookie header.")
        text = "# Netscape HTTP Cookie File\n" + "\n".join(rows) + "\n"
        count = len(rows)

    path = os.path.join(temp_dir, "cookies.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print("vault leech: loaded %s cookie records for %s" % (count, platform), flush=True)
    return path
def _friendly(raw, platform="youtube"):
    low = raw.lower()
    if platform == "youtube":
        if "failed to extract any player response" in low or "player response" in low:
            return "YouTube did not return a usable player response. The updated extractor will retry; if it persists, the host may be temporarily blocking the request."
        if "javascript runtime" in low or "n challenge" in low or "ejs" in low:
            return "YouTube's format check needs the JavaScript runtime. Check the latest service build and runtime logs."
        if "sign in to confirm" in low or "login required" in low:
            return "YouTube requires an authorized session for this video. Public videos should work without cookies."
        if "http error 403" in low or "server returned 403" in low:
            return "YouTube returned HTTP 403 for the media file. The server/CDN denied access; this is not a URL-format problem, and automatic retries will not fix the denial. Use a download supplied or authorized by the video owner."
    else:
        if "exceeded the rate-limit" in low or "redirected to the login page" in low:
            return "Instagram requires an authenticated session or has rate-limited this server."
        if "failed to parse json" in low or "jsondecodeerror" in low:
            return "Instagram returned an invalid response. Vault Leech is pausing the queue and will retry later."
        if "empty media response" in low or any(x in low for x in _THROTTLE[1:]):
            return "Instagram temporarily rate-limited this request. It will retry after a cooldown."
        if "private" in low or "login required" in low:
            return "This Reel is not publicly downloadable."
    return raw.replace("ERROR: ", "")[:200]


def _failure(job, exc):
    raw = str(exc).strip() or "Download failed."
    low = raw.lower()
    platform = _platform(job["url"])
    auth_blocked = platform == "instagram" and (
        "exceeded the rate-limit" in low or "redirected to the login page" in low
    ) and not os.environ.get("IG_COOKIES", "").strip()
    throttled = any(x in low for x in _THROTTLE) and not auth_blocked
    youtube_403 = platform == "youtube" and ("http error 403" in low or "server returned 403" in low)
    permanent = auth_blocked or youtube_403 or (not throttled and any(x in low for x in _PERMANENT))
    attempts = int(job.get("attempts") or 1)
    if throttled:
        _COOL["until"] = time.time() + min(900, 90 * attempts)
    if not permanent and attempts < MAX_ATTEMPTS:
        delay = min(1800, 30 * 2 ** (attempts - 1)) + random.uniform(0, 10)
        Q.update(job["id"], status="queued", next_try=time.time()+delay, percent=0,
                 message="Retry %s/%s in %ss · %s" % (
                     attempts, MAX_ATTEMPTS-1, int(delay), _friendly(raw, platform)[:110]))
    else:
        Q.update(job["id"], status="failed", message=_friendly(raw, platform))


_YTJS_LOCK = threading.Lock()
_YTJS_READY = False

def _ensure_youtubejs():
    """Install the pinned YouTube.js package once if the Render build did not."""
    global _YTJS_READY
    if _YTJS_READY:
        return
    with _YTJS_LOCK:
        if _YTJS_READY:
            return
        root = os.path.dirname(os.path.abspath(__file__))
        package_dir = os.path.join(root, "node_modules", "youtubei.js")
        if not os.path.isdir(package_dir):
            npm = shutil.which("npm")
            node = shutil.which("node")
            if not npm or not node:
                raise RuntimeError("YouTube.js needs Node.js and npm on this service. Add Node.js to the Render runtime and redeploy.")
            result = subprocess.run(
                [npm, "install", "--no-save", "--no-audit", "--no-fund", "youtubei.js@18.3.0"],
                cwd=root, capture_output=True, text=True, timeout=300
            )
            if result.returncode:
                detail = (result.stderr or result.stdout or "npm install failed").strip()
                raise RuntimeError("Could not install YouTube.js: " + detail[-500:])
        _YTJS_READY = True


def _download_youtube(url, output_path, job_id):
    """Download through YouTube.js; Instagram remains on its existing engine."""
    _ensure_youtubejs()
    root = os.path.dirname(os.path.abspath(__file__))
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is not available for the YouTube.js downloader.")
    helper = os.path.join(root, "youtube_worker.mjs")
    log_output = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    proc = subprocess.Popen(
        [node, helper, url, output_path],
        cwd=root, stdout=log_output, stderr=subprocess.STDOUT,
        text=True
    )
    last_update = 0.0
    while proc.poll() is None:
        now = time.time()
        if now - last_update >= 2:
            last_update = now
            try:
                size = os.path.getsize(output_path)
            except OSError:
                size = 0
            if size:
                Q.update(job_id, percent=min(75, max(2, int(size / (5 * 1024 * 1024)))),
                         message="Vault Leech · YouTube.js · " + str(round(size / 1048576, 1)) + " MB received")
        time.sleep(0.5)
    proc.wait()
    log_output.seek(0)
    output = log_output.read() or ""
    log_output.close()
    if proc.returncode != 0:
        try:
            result = json.loads(output.strip().splitlines()[-1])
            message = result.get("error") or "YouTube.js download failed."
        except Exception:
            message = output.strip()[-500:] or "YouTube.js download failed."
        raise RuntimeError(message)
    try:
        result = json.loads(output.strip().splitlines()[-1])
    except Exception:
        raise RuntimeError("YouTube.js finished without returning download details.")
    if not os.path.isfile(output_path) or os.path.getsize(output_path) <= 0:
        raise RuntimeError("YouTube.js returned an empty video file.")
    return {"title": result.get("title") or "YouTube video", "id": result.get("id") or ""}


def _process(job, store_file):
    import yt_dlp
    jid = job["id"]
    platform = _platform(job["url"])
    label = "YouTube video" if platform == "youtube" else "Instagram Reel"
    if job.get("file_id"):
        Q.update(jid, status="completed", percent=100,
                 message="Already saved in your Discord Vault · Reels")
        return
    folder = tempfile.mkdtemp(prefix="vault-leech-")
    last = [0.0]
    try:
        def progress(d):
            now = time.time()
            if d.get("status") == "downloading" and now-last[0] > 2:
                last[0] = now
                total = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
                pct = min(79, int((d.get("downloaded_bytes") or 0)*79/total)) if total else 1
                Q.update(jid, percent=pct, message="Vault Leech · Downloading · " +
                         (str(d.get("_percent_str", "")).strip() or "working"))

        if platform == "youtube":
            # YouTube.js is a separate InnerTube implementation. It reads the
            # existing YT_COOKIES / YOUTUBE_COOKIES secret without logging it.
            path = os.path.join(folder, "youtube-video.mp4")
            info = _download_youtube(job["url"], path, jid)
        else:
            opts = {
                "format": "best[ext=mp4]/best",
                "outtmpl": os.path.join(folder, "%(id)s.%(ext)s"),
                "noplaylist": True, "quiet": True, "no_warnings": True,
                "restrictfilenames": True, "socket_timeout": 45,
                "retries": 3, "fragment_retries": 3, "extractor_retries": 3,
                "file_access_retries": 2, "max_filesize": MAX_BYTES,
                "progress_hooks": [progress],
                "js_runtimes": {"node": {}}
            }
            cookie_path = _cookie_file(folder, platform)
            if cookie_path:
                opts["cookiefile"] = cookie_path
            with yt_dlp.YoutubeDL(opts) as dl:
                info = dl.extract_info(job["url"], download=True)
                if not info:
                    raise RuntimeError(platform.capitalize() + " did not provide a downloadable video.")
                path = dl.prepare_filename(info)
        if not os.path.isfile(path):
            candidates = [os.path.join(folder, n) for n in os.listdir(folder)
                          if n != "cookies.txt" and os.path.isfile(os.path.join(folder, n))]
            if not candidates:
                raise RuntimeError("The downloaded video file was not found.")
            path = candidates[0]
        base = os.path.basename(str(info.get("title") or info.get("id") or label))
        base = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', " ", base)
        ext = os.path.splitext(path)[1].lower()
        if not re.fullmatch(r"\.[a-z0-9]{1,8}", ext):
            ext = ".mp4"
        filename = (re.sub(r"\s+", " ", base).strip(" .")[:130] or label) + ext
        Q.update(jid, status="storing", percent=80, title=filename,
                 message="Vault Leech · Encrypting and saving to Discord…")
        fid = store_file(path, filename, jid, job["url"])
        Q.update(jid, status="completed", percent=100, file_id=fid, title=filename,
                 message="Saved in your Discord Vault · Reels")
    except Exception as exc:
        _failure(job, exc)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _worker(store_file, load_worker_key):
    while True:
        try:
            load_worker_key()
            if time.time() < _COOL["until"]:
                _WAKE.wait(8); _WAKE.clear(); continue
            job = Q.claim()
            if not job:
                _WAKE.wait(8); _WAKE.clear(); continue
            _process(job, store_file)
            time.sleep(random.uniform(2, 5))
        except Exception as exc:
            print("vault leech worker error:", str(exc)[:180], flush=True)
            time.sleep(10)


def register(app, authed, store_file, load_worker_key):
    global _STARTED

    @app.post("/api/reels/download")
    def leech_submit():
        if not authed():
            abort(403)
        urls = (request.get_json(silent=True) or {}).get("urls") or []
        if not isinstance(urls, list):
            return "Send a list of supported YouTube or Instagram video URLs.", 400
        if len(urls) > BATCH_MAX:
            return "Batch limit is 1000 links.", 413
        good, seen, invalid, duplicates = [], set(), 0, 0
        for raw in urls:
            url = valid_url(raw)
            if not url:
                invalid += 1
            elif url in seen:
                duplicates += 1
            else:
                seen.add(url)
                good.append(url)
        try:
            added, dup, requeued = Q.add_many(good) if good else (0, 0, 0)
        except Exception as exc:
            return "Leech queue storage failed: " + str(exc)[:160], 503
        _WAKE.set()
        return jsonify(submitted=len(urls), added=added, requeued=requeued,
                       duplicates=dup+duplicates, invalid=invalid, summary=Q.summary())

    @app.get("/api/reels/jobs")
    def leech_jobs():
        if not authed():
            abort(403)
        try:
            limit = min(200, max(1, int(request.args.get("limit", 50))))
            offset = max(0, int(request.args.get("offset", 0)))
            return jsonify(jobs=Q.listing(limit, offset, request.args.get("status")),
                           summary=Q.summary())
        except Exception as exc:
            return "Leech queue read failed: " + str(exc)[:160], 503

    @app.post("/api/reels/retry_failed")
    def leech_retry():
        if not authed():
            abort(403)
        n = Q.retry_failed()
        _WAKE.set()
        return jsonify(requeued=n, summary=Q.summary())

    if not _STARTED:
        Q.init()
        for _ in range(2):
            threading.Thread(target=_worker, args=(store_file, load_worker_key), daemon=True).start()
        _STARTED = True
