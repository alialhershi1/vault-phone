"""Phone interface for the encrypted Discord vault. Runs behind Render's HTTPS proxy."""
import base64, datetime, ipaddress, json, random, mimetypes, os, re, secrets, socket, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlparse
import requests
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Flask, abort, jsonify, request, send_from_directory
import vault_server as V
import reel_queue as Q
import imageio_ffmpeg

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "10000"))
app = Flask(__name__)
_lock = threading.RLock()
SCAN_LOCK = threading.RLock()
LIB = {"t": 0, "items": []}
NAMES = {}
META_CACHE = {}
SCAN_FOUND = {}
SCAN_BEFORE = None
SCAN_DONE = False
SCAN_BUSY = False
SCAN_ERROR = ""
FAILS = []
UPLOADS = {}
GROUP_RECORDS = {}
ASSIGN_RECORDS = {}

# ---------------------------------------------------------------------------
# Stateless sessions: the token is an AES-GCM blob (key wrapped with a server
# secret + expiry). Any instance, and any restart, can validate it. The vault
# password check / PBKDF2 derivation is unchanged.
# ---------------------------------------------------------------------------
SESSION_TTL = 30 * 86400
_WRAP = AESGCM(HKDF(SHA256(), 32, None, b"vault-phone-session-v1").derive(
    (os.environ.get("SESSION_SECRET") or V.TOKEN).encode()))

def make_token(raw_key, ttl=SESSION_TTL):
    iv = os.urandom(12)
    body = json.dumps({"e": int(time.time()) + ttl, "k": raw_key.hex()}).encode()
    return base64.urlsafe_b64encode(iv + _WRAP.encrypt(iv, body, None)).decode().rstrip("=")

def read_token(tok):
    try:
        blob = base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4))
        d = json.loads(_WRAP.decrypt(blob[:12], blob[12:], None))
        return bytes.fromhex(d["k"]) if d["e"] > time.time() else None
    except Exception:
        return None

def _set_key(raw):
    if V.KEY.get("raw") != raw:
        V.KEY["aes"], V.KEY["raw"] = AESGCM(raw), raw
        _persist_worker_key(raw)
    _WAKE.set()

def authed():
    raw = read_token(request.args.get("t", "") or request.headers.get("X-Vault-Token", ""))
    if not raw:
        return False
    _set_key(raw)
    return True
V.AUTH_CHECK = authed

# Reel downloads: a durable queue (reel_queue.py) drained by exactly 2 workers.
_REEL_MAX_BYTES = 500 * 1024 * 1024
_WAKE = threading.Event()
_IG = {"cool": 0.0}
_PERSISTED = {"raw": None}
MAX_ATTEMPTS = 5
BATCH_MAX = 1000
_THROTTLE = ("empty media response", "rate-limit", "rate limit", "429", "too many requests", "not granting access")
_PERMANENT = ("private", "login required", "unavailable", "removed", "does not exist", "not found", "404", "age-restricted", "exceeds the 500")

def _persist_worker_key(raw):
    """Lets queued downloads resume after a restart without anyone unlocking.
    Stored wrapped (needs this server's env secret). Disable: WORKER_KEY_PERSIST=0."""
    if not Q.DURABLE or os.environ.get("WORKER_KEY_PERSIST", "1") == "0" or _PERSISTED["raw"] == raw:
        return
    try:
        Q.kv_set("worker_key", make_token(raw, 365 * 86400))
        _PERSISTED["raw"] = raw
    except Exception:
        pass

def _load_worker_key():
    if not Q.DURABLE or os.environ.get("WORKER_KEY_PERSIST", "1") == "0":
        return
    try:
        raw = read_token(Q.kv_get("worker_key") or "")
        if raw:
            V.KEY["aes"], V.KEY["raw"] = AESGCM(raw), raw
            _PERSISTED["raw"] = raw
    except Exception:
        pass

def _valid_instagram_reel_url(raw):
    try:
        parsed = urlparse(str(raw).strip())
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in ("http", "https") or host not in {"instagram.com", "www.instagram.com", "m.instagram.com"}:
            return None
        m = re.match(r"^/(?:[^/]+/)?(?:reel|reels)/([A-Za-z0-9_-]+)", parsed.path)
        return "https://www.instagram.com/reel/" + m.group(1) + "/" if m else None
    except Exception:
        return None

def _safe_reel_filename(title, extension):
    base = os.path.basename(str(title or "Instagram Reel"))
    base = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', " ", base)
    base = re.sub(r"\s+", " ", base).strip(" .")[:130] or "Instagram Reel"
    ext = re.sub(r"[^a-z0-9]", "", str(extension or "mp4").lower())[:8] or "mp4"
    return base + "." + ext

def _store_downloaded_reel(path, filename, job_id, src_url):
    size = os.path.getsize(path)
    if size <= 0 or size > _REEL_MAX_BYTES:
        raise RuntimeError("The downloaded video is empty or exceeds the 500 MB limit.")
    mime = mimetypes.guess_type(filename)[0] or "video/mp4"
    fid = secrets.token_hex(6)
    n = max(1, (size + V.CHUNK - 1) // V.CHUNK)
    t = int(time.time() * 1000)
    meta = {"name": filename, "folder": "Reels", "type": mime, "size": size, "t": t, "src": src_url}
    created_ids, last_url, ok = [], None, False
    try:
        # Chunks first, meta LAST: the library only lists an entry once it is complete.
        sent, chunk_urls = 0, {}
        with open(path, "rb") as source:
            for index in range(n):
                chunk = source.read(V.CHUNK)
                if not chunk:
                    raise RuntimeError("The temporary video file ended unexpectedly.")
                msg = V.dc("POST", f"/channels/{V.CH}/messages", data={"content": f"v1 {fid} c{index} {n}"},
                           files={"files[0]": (f"{fid}.{index}.bin", seal(chunk))}).json()
                created_ids.append(msg.get("id"))
                chunk_urls[index] = msg["attachments"][0]["url"]
                sent += len(chunk)
                Q.update(job_id, status="storing", percent=80 + int(18 * sent / size),
                         message=f"Sending to Discord · {index + 1}/{n} parts")
        # Verify the last chunk is really retrievable before calling this a success.
        probe = requests.get(chunk_urls[n - 1], headers={"Range": "bytes=0-15"}, timeout=60)
        if probe.status_code not in (200, 206):
            raise RuntimeError("Discord stored the video but could not read it back (%s)." % probe.status_code)
        msg = V.dc("POST", f"/channels/{V.CH}/messages", data={"content": f"v1 {fid} m {n}"},
                   files={"files[0]": (f"m{fid}.bin", seal(json.dumps(meta).encode()))}).json()
        created_ids.append(msg.get("id"))
        with SCAN_LOCK:
            SCAN_FOUND[fid] = {"meta": msg["attachments"][0]["url"], "chunks": chunk_urls, "n": n,
                               "message_ids": list(created_ids)}
            META_CACHE[fid] = {"id": fid, "name": filename, "folder": "Reels", "type": mime, "size": size, "t": t}
        with _lock:
            LIB.update(t=0, items=[])
        ok = True
        return fid
    finally:
        if not ok:
            for mid in created_ids:
                if mid:
                    try:
                        V.dc("DELETE", f"/channels/{V.CH}/messages/{mid}")
                    except Exception:
                        pass

def _friendly(msg):
    low = msg.lower()
    if "empty media response" in low or any(k in low for k in _THROTTLE[1:]):
        return "Instagram refused the request (rate limit, private post, or login needed)."
    if "private" in low or "login required" in low:
        return "This Reel is not publicly downloadable."
    return msg.replace("ERROR: ", "")[:200]

def _handle_failure(job, exc):
    raw = str(exc).strip() or "Download failed."
    low = raw.lower()
    throttled = any(k in low for k in _THROTTLE)
    permanent = (not throttled) and any(k in low for k in _PERMANENT)
    attempts = int(job.get("attempts") or 1)
    if throttled:
        _IG["cool"] = time.time() + min(900, 90 * attempts)  # both workers back off
    if not permanent and attempts < MAX_ATTEMPTS:
        delay = min(1800, 30 * 2 ** (attempts - 1)) + random.uniform(0, 10)
        Q.update(job["id"], status="queued", next_try=time.time() + delay, percent=0,
                 message=f"Retry {attempts}/{MAX_ATTEMPTS - 1} in {int(delay)}s · {_friendly(raw)[:110]}")
    else:
        Q.update(job["id"], status="failed", message=_friendly(raw))

def _process(job):
    import shutil, yt_dlp
    jid = job["id"]
    if job.get("file_id"):  # already stored on an earlier attempt: never download twice
        Q.update(jid, status="completed", percent=100, message="Saved in your Discord Vault · Reels")
        return
    temp_dir = tempfile.mkdtemp(prefix="vault-reel-")
    last = [0.0]
    try:
        def progress(d):
            now = time.time()
            if d.get("status") == "downloading" and now - last[0] > 2:
                last[0] = now
                tot = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
                pct = min(79, int((d.get("downloaded_bytes") or 0) * 79 / tot)) if tot else 1
                Q.update(jid, percent=pct, message="Downloading from Instagram · " + (str(d.get("_percent_str", "")).strip() or "working"))
        options = {"format": "bestvideo+bestaudio/best", "merge_output_format": "mp4",
                   "ffmpeg_location": imageio_ffmpeg.get_ffmpeg_exe(),
                   "outtmpl": os.path.join(temp_dir, "%(id)s.%(ext)s"),
                   "noplaylist": True, "quiet": True, "no_warnings": True, "restrictfilenames": True,
                   "socket_timeout": 30, "retries": 2, "fragment_retries": 2, "extractor_retries": 1,
                   "max_filesize": _REEL_MAX_BYTES, "progress_hooks": [progress]}
        cookies = os.environ.get("IG_COOKIES", "").strip()
        if cookies:
            cf = os.path.join(temp_dir, "cookies.txt")
            with open(cf, "w") as fh:
                fh.write(cookies + "\n")
            options["cookiefile"] = cf
        with yt_dlp.YoutubeDL(options) as dl:
            info = dl.extract_info(job["url"], download=True)
            if not info:
                raise RuntimeError("Instagram did not provide a downloadable video.")
            filepath = dl.prepare_filename(info)
        if not os.path.isfile(filepath):
            cands = [os.path.join(temp_dir, x) for x in os.listdir(temp_dir) if x != "cookies.txt"]
            cands = [p for p in cands if os.path.isfile(p)]
            if not cands:
                raise RuntimeError("The downloaded video file was not found.")
            filepath = cands[0]
        filename = _safe_reel_filename(info.get("title") or info.get("id"), os.path.splitext(filepath)[1].lstrip("."))
        Q.update(jid, status="storing", percent=80, title=filename, message="Encrypting and sending video to Discord…")
        fid = _store_downloaded_reel(filepath, filename, jid, job["url"])
        Q.update(jid, status="completed", percent=100, file_id=fid, title=filename, message="Saved in your Discord Vault · Reels")
    except Exception as exc:
        _handle_failure(job, exc)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def _worker_loop():
    while True:
        try:
            if not V.KEY.get("aes"):
                _load_worker_key()
            if not V.KEY.get("aes") or time.time() < _IG["cool"]:
                _WAKE.wait(8); _WAKE.clear(); continue
            job = Q.claim()
            if not job:
                _WAKE.wait(8); _WAKE.clear(); continue
            _process(job)
            time.sleep(random.uniform(2, 5))  # be gentle with Instagram
        except Exception as exc:
            print("reel worker error:", exc, flush=True)
            time.sleep(10)

def _keepalive_loop():
    base = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
    while base:
        time.sleep(600)
        try:
            if Q.summary()["active"] > 0:  # free web services sleep after 15 min without traffic
                requests.get(base + "/health", timeout=20)
        except Exception:
            pass

def _start_reel_workers():
    Q.init()
    for _ in range(2):  # concurrency stays at 2
        threading.Thread(target=_worker_loop, daemon=True).start()
    threading.Thread(target=_keepalive_loop, daemon=True).start()

@app.post("/api/reels/download")
def reels_download():
    if not authed():
        abort(403)
    raw_urls = (request.get_json(silent=True) or {}).get("urls") or []
    if not isinstance(raw_urls, list):
        return "Send a list of Instagram Reel URLs.", 400
    if len(raw_urls) > BATCH_MAX:
        return f"Send at most {BATCH_MAX} links per request.", 413
    good, seen, invalid, samples, in_batch_dups = [], set(), 0, [], 0
    for raw in raw_urls:
        url = _valid_instagram_reel_url(raw)
        if not url:
            invalid += 1
            if len(samples) < 5:
                samples.append(str(raw)[:80])
        elif url in seen:
            in_batch_dups += 1
        else:
            seen.add(url); good.append(url)
    added = dup = requeued = 0
    if good:
        try:
            added, dup, requeued = Q.add_many(good)
        except Exception as exc:
            return "Queue storage failed: " + str(exc)[:200], 503
        _WAKE.set()
    return jsonify(submitted=len(raw_urls), added=added, requeued=requeued, duplicates=dup + in_batch_dups,
                   invalid=invalid, invalid_samples=samples, summary=Q.summary())

@app.get("/api/reels/jobs")
def reels_jobs():
    if not authed():
        abort(403)
    try:
        limit = min(200, max(1, int(request.args.get("limit", 50))))
        offset = max(0, int(request.args.get("offset", 0)))
        return jsonify(jobs=Q.listing(limit, offset, request.args.get("status")), summary=Q.summary())
    except Exception as exc:
        return "Queue read failed: " + str(exc)[:200], 503

@app.post("/api/reels/retry_failed")
def reels_retry_failed():
    if not authed():
        abort(403)
    n = Q.retry_failed()
    _WAKE.set()
    return jsonify(requeued=n, summary=Q.summary())

def _add_messages(msgs):
    global SCAN_FOUND
    with SCAN_LOCK:
        for msg in msgs:
            p = msg.get("content", "").split()
            attachments = msg.get("attachments") or []
            if not p or not attachments:
                continue
            url = attachments[0]["url"]
            if p[0] == "v1g" and len(p) >= 2:
                GROUP_RECORDS.setdefault(p[1], url)
                continue
            if p[0] == "v1a" and len(p) >= 3:
                ASSIGN_RECORDS.setdefault(p[1], []).append((p[2], url))
                continue
            if len(p) < 4 or p[0] != "v1":
                continue
            try:
                n = int(p[3])
            except (TypeError, ValueError):
                continue
            fid = p[1]
            f = SCAN_FOUND.setdefault(fid, {"chunks": {}, "n": n, "message_ids": []})
            f.setdefault("message_ids", []).append(msg.get("id"))
            if p[2] == "m":
                f["meta"] = url
            elif p[2].startswith("c"):
                try:
                    f["chunks"][int(p[2][1:])] = url
                except ValueError:
                    pass

def _get_page(before=None):
    params = {"limit": 100}
    if before:
        params["before"] = before
    return V.dc("GET", f"/channels/{V.CH}/messages", params=params).json()

def verify(aes):
    """Validate using the newest metadata available, then seed the background scan."""
    global SCAN_BEFORE, SCAN_DONE, SCAN_ERROR
    before = None
    while True:
        msgs = _get_page(before)
        _add_messages(msgs)
        page_metas = []
        for msg in msgs:
            p = msg.get("content", "").split()
            if len(p) >= 4 and p[0] == "v1" and p[2] == "m" and msg.get("attachments"):
                page_metas.append(msg["attachments"][0]["url"])
        if page_metas:
            for url in page_metas:
                try:
                    r = requests.get(url, timeout=20)
                    r.raise_for_status()
                    c = r.content
                    if len(c) > 12:
                        aes.decrypt(c[:12], c[12:], None)
                        SCAN_BEFORE = msgs[-1]["id"] if len(msgs) == 100 else None
                        SCAN_DONE = len(msgs) < 100
                        SCAN_ERROR = ""
                        return True
                except Exception:
                    continue
            return False
        if len(msgs) < 100:
            SCAN_BEFORE = None
            SCAN_DONE = True
            SCAN_ERROR = ""
            return True
        before = msgs[-1]["id"]

def _scan_worker():
    global SCAN_BEFORE, SCAN_DONE, SCAN_BUSY, SCAN_ERROR
    try:
        while True:
            with SCAN_LOCK:
                before = SCAN_BEFORE
                if SCAN_DONE:
                    break
            msgs = _get_page(before)
            _add_messages(msgs)
            with SCAN_LOCK:
                if len(msgs) < 100:
                    SCAN_BEFORE = None
                    SCAN_DONE = True
                    break
                SCAN_BEFORE = msgs[-1]["id"]
                SCAN_ERROR = ""
    except Exception as e:
        with SCAN_LOCK:
            SCAN_ERROR = str(e)[:300]
    finally:
        with SCAN_LOCK:
            SCAN_BUSY = False

def start_scan():
    global SCAN_BUSY
    with SCAN_LOCK:
        if SCAN_DONE or SCAN_BUSY:
            return
        SCAN_BUSY = True
    threading.Thread(target=_scan_worker, daemon=True).start()

def _library_snapshot():
    with SCAN_LOCK:
        return {k: {"meta": v.get("meta"), "chunks": dict(v["chunks"]), "n": v["n"], "message_ids": list(v.get("message_ids", []))}
                for k, v in SCAN_FOUND.items() if v.get("meta")}

def library():
    found = _library_snapshot()
    def one(kv):
        fid, f = kv
        with SCAN_LOCK:
            cached = META_CACHE.get(fid)
        if cached is None:
            try:
                r = requests.get(f["meta"], timeout=15)
                r.raise_for_status()
                m = json.loads(V.KEY["aes"].decrypt(r.content[:12], r.content[12:], None))
                cached = {"id": fid, "name": m.get("name", "?"), "folder": m.get("folder") or "",
                          "type": m.get("type") or "", "size": m.get("size", 0), "t": m.get("t", 0)}
                with SCAN_LOCK:
                    META_CACHE[fid] = cached
            except Exception:
                return None
        item = dict(cached)
        item["ok"] = len(f["chunks"]) == f["n"]
        return item
    with ThreadPoolExecutor(max_workers=8) as ex:
        items = [x for x in ex.map(one, found.items()) if x]
    items.sort(key=lambda x: x["t"], reverse=True)
    with _lock:
        LIB.update(t=time.time(), items=items)
        NAMES.clear()
        NAMES.update({x["id"]: x for x in items})
    with SCAN_LOCK:
        scanning, error = (not SCAN_DONE) or SCAN_BUSY, SCAN_ERROR
    return {"items": items, "scanning": scanning, "error": error}

def end_session():
    V.KEY["aes"] = V.KEY["token"] = None
    V.clear_stream_state()
    with _lock:
        LIB.update(t=0, items=[])
        NAMES.clear()
    with SCAN_LOCK:
        global SCAN_FOUND, SCAN_BEFORE, SCAN_DONE, SCAN_BUSY, SCAN_ERROR
        SCAN_FOUND, SCAN_BEFORE, SCAN_DONE, SCAN_BUSY, SCAN_ERROR = {}, None, False, False, ""
        META_CACHE.clear()
        GROUP_RECORDS.clear()
        ASSIGN_RECORDS.clear()

@app.get("/")
def index():
    r = send_from_directory(HERE, "phone_v2.html")
    r.headers["Cache-Control"] = "no-store"
    return r

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/api/unlock")
def unlock():
    now = time.time()
    FAILS[:] = [x for x in FAILS if now - x < 300]
    if len(FAILS) >= 8:
        return "Too many wrong tries. Wait a few minutes.", 429
    pw = (request.get_json(silent=True) or {}).get("p", "")
    if not pw:
        return "Enter the vault password.", 400
    raw = PBKDF2HMAC(SHA256(), 32, b"vault-v1", 300000).derive(pw.encode())
    aes = AESGCM(raw)
    with SCAN_LOCK:
        global SCAN_FOUND, SCAN_BEFORE, SCAN_DONE, SCAN_BUSY, SCAN_ERROR
        SCAN_FOUND, SCAN_BEFORE, SCAN_DONE, SCAN_BUSY, SCAN_ERROR = {}, None, False, False, ""
        META_CACHE.clear()
    try:
        valid = verify(aes)
    except Exception as e:
        return ("Vault check failed: " + str(e)[:250]), 503
    if not valid:
        FAILS.append(now)
        time.sleep(0.5)
        return "Incorrect vault password.", 401
    V.clear_stream_state()
    V.KEY["aes"], V.KEY["raw"] = aes, raw
    _persist_worker_key(raw)
    _WAKE.set()
    with _lock:
        LIB.update(t=0, items=[])
    start_scan()
    return jsonify(t=make_token(raw))

@app.post("/api/lock")
def lock():
    # Sessions are stateless and shared by every device, and queued downloads
    # need the key, so "lock" only drops this device's token (done client-side).
    return "", 204

@app.get("/api/library")
def lib():
    if not authed():
        abort(403)
    start_scan()
    return jsonify(library())

def _post_encrypted_record(content, payload, filename):
    r = V.dc("POST", f"/channels/{V.CH}/messages", data={"content": content},
             files={"files[0]": (filename, seal(json.dumps(payload).encode()))})
    r.raise_for_status()
    return r.json()

@app.get("/api/groups")
def get_groups():
    if not authed():
        abort(403)
    groups = []
    for gid, url in list(GROUP_RECORDS.items()):
        try:
            raw = requests.get(url, timeout=15).content
            data = json.loads(V.KEY["aes"].decrypt(raw[:12], raw[12:], None))
            groups.append({"id": gid, "name": str(data.get("name", "Folder")), "color": str(data.get("color", "#64748b"))})
        except Exception:
            continue
    assignments = {}
    for fid, records in list(ASSIGN_RECORDS.items()):
        if records:
            gid, url = records[0]
            try:
                raw = requests.get(url, timeout=15).content
                data = json.loads(V.KEY["aes"].decrypt(raw[:12], raw[12:], None))
                assignments[fid] = data.get("group", "")
            except Exception:
                assignments[fid] = gid
    return jsonify(groups=groups, assignments=assignments)

@app.post("/api/groups")
def create_group():
    if not authed():
        abort(403)
    name = str((request.get_json(silent=True) or {}).get("name", "")).strip()[:60]
    if not name:
        return "Enter a folder name.", 400
    gid = secrets.token_hex(6)
    msg = _post_encrypted_record(f"v1g {gid}", {"name": name}, f"g{gid}.bin")
    GROUP_RECORDS[gid] = msg["attachments"][0]["url"]
    return jsonify(id=gid, name=name)

@app.post("/api/groups/color")
def set_group_color():
    if not authed():
        abort(403)
    d = request.get_json(silent=True) or {}
    gid = str(d.get("id", ""))
    color = str(d.get("color", "")).lower()
    allowed = {"#3b82f6", "#ef4444", "#22c55e", "#a855f7", "#f97316",
               "#eab308", "#ec4899", "#14b8a6", "#06b6d4", "#64748b"}
    if gid not in GROUP_RECORDS or color not in allowed:
        return "Folder or color not found.", 400
    old_url = GROUP_RECORDS[gid]
    old_raw = requests.get(old_url, timeout=15).content
    old_data = json.loads(V.KEY["aes"].decrypt(old_raw[:12], old_raw[12:], None))
    msg = _post_encrypted_record(f"v1g {gid}", {
        "name": str(old_data.get("name", "Folder")), "color": color
    }, f"g{gid}.bin")
    GROUP_RECORDS[gid] = msg["attachments"][0]["url"]
    return jsonify(id=gid, color=color)
@app.post("/api/groups/assign")
def assign_group():
    if not authed():
        abort(403)
    d = request.get_json(silent=True) or {}
    fid, gid = str(d.get("file", "")), str(d.get("group", ""))
    if fid not in NAMES or (gid and gid not in GROUP_RECORDS):
        return "File or folder not found.", 404
    stored_gid = gid or "none"
    msg = _post_encrypted_record(f"v1a {fid} {stored_gid}", {"group": gid}, f"a{fid}.bin")
    ASSIGN_RECORDS.setdefault(fid, []).insert(0, (stored_gid, msg["attachments"][0]["url"]))
    return "", 204

@app.delete("/api/files/<fid>")
def delete_file(fid):
    if not authed():
        abort(403)
    with SCAN_LOCK:
        found = SCAN_FOUND.get(fid)
        ids = list(found.get("message_ids", [])) if found else []
    if not ids:
        return "File not found.", 404
    for mid in ids:
        if mid:
            try:
                V.dc("DELETE", f"/channels/{V.CH}/messages/{mid}")
            except requests.HTTPError as e:
                if e.response is None or e.response.status_code != 404:  # already gone is fine
                    raise
    with SCAN_LOCK:
        SCAN_FOUND.pop(fid, None)
        META_CACHE.pop(fid, None)
        ASSIGN_RECORDS.pop(fid, None)
    with _lock:
        LIB.update(t=0, items=[])
        NAMES.pop(fid, None)
    return "", 204

@app.get("/api/stream/<fid>")
def stream(fid):
    # Reuse the phone app's indexed Discord message URLs. Otherwise the
    # streaming helper performs a fresh full channel scan per new video.
    with SCAN_LOCK:
        found = SCAN_FOUND.get(fid)
        item = META_CACHE.get(fid)
        if found and item and len(found["chunks"]) == found["n"]:
            info = {"chunks": dict(found["chunks"]), "n": found["n"],
                    "size": int(item.get("size") or 0), "type": item.get("type") or ""}
            with V._flock:
                V._files[fid] = (time.time(), info)
    r = V.stream(fid)
    it = NAMES.get(fid)
    if it:
        if r.mimetype == "application/octet-stream":
            mt = mimetypes.guess_type(it["name"])[0]
            if mt:
                r.mimetype = mt
        if request.args.get("dl"):
            r.headers["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(it["name"])
    return r

def seal(data):
    iv = os.urandom(12)
    return iv + V.KEY["aes"].encrypt(iv, data, None)

@app.post("/api/upload/start")
def upload_start():
    if not authed():
        abort(403)
    d = request.get_json(silent=True) or {}
    name = os.path.basename(str(d.get("name") or "file").replace("\\", "/"))[:200] or "file"
    raw_folder = str(d.get("folder") or "").replace("\\", "/").strip("/")
    folder_parts = [part[:100] for part in raw_folder.split("/") if part and part not in (".", "..")]
    folder = "/".join(folder_parts)[:400]
    size = max(0, int(d.get("size", 0)))
    mime = str(d.get("type") or mimetypes.guess_type(name)[0] or "")
    n = max(1, -(-size // V.CHUNK))
    fid = secrets.token_hex(6)
    meta = json.dumps({"name": name, "folder": folder, "type": mime, "size": size,
                       "t": int(time.time() * 1000)}).encode()
    resp = V.dc("POST", f"/channels/{V.CH}/messages", data={"content": f"v1 {fid} m {n}"}, files={"files[0]": (f"m{fid}.bin", seal(meta))})
    try:
        url = resp.json()["attachments"][0]["url"]
        with SCAN_LOCK:
            SCAN_FOUND[fid] = {"meta": url, "chunks": {}, "n": n, "message_ids": [resp.json().get("id")]}
            META_CACHE[fid] = {"id": fid, "name": name, "folder": folder, "type": mime,
                               "size": size, "t": int(time.time() * 1000)}
    except Exception:
        pass
    UPLOADS[fid] = {"n": n}
    return jsonify(id=fid, n=n, chunk=V.CHUNK)

@app.post("/api/upload/chunk")
def upload_chunk():
    if not authed():
        abort(403)
    fid = request.args.get("id", "")
    try:
        i = int(request.args.get("i", "-1"))
    except ValueError:
        abort(400)
    u = UPLOADS.get(fid)
    if not u or not 0 <= i < u["n"]:
        abort(400)
    data = request.get_data()
    if len(data) > V.CHUNK:
        abort(413)
    resp = V.dc("POST", f"/channels/{V.CH}/messages", data={"content": f"v1 {fid} c{i} {u['n']}"}, files={"files[0]": (f"{fid}.{i}.bin", seal(data))})
    try:
        url = resp.json()["attachments"][0]["url"]
        with SCAN_LOCK:
            if fid in SCAN_FOUND:
                SCAN_FOUND[fid]["chunks"][i] = url
                SCAN_FOUND[fid].setdefault("message_ids", []).append(resp.json().get("id"))
    except Exception:
        pass
    if i == u["n"] - 1:
        UPLOADS.pop(fid, None)
        with _lock:
            LIB.update(t=0, items=[])
    return "", 204

_start_reel_workers()
