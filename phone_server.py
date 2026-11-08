"""Phone interface for the encrypted Discord vault. Runs behind Render's HTTPS proxy."""
import datetime, ipaddress, json, mimetypes, os, re, secrets, socket, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlparse
import requests
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, abort, jsonify, request, send_from_directory
import vault_server as V

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

# Instagram Reel downloads run on the server; the browser sends URLs only.
_REEL_JOBS = {}
_REEL_JOB_LOCK = threading.RLock()
_REEL_EXECUTOR = ThreadPoolExecutor(max_workers=2)
_REEL_MAX_BYTES = 500 * 1024 * 1024

def _reel_job_update(job_id, **values):
    with _REEL_JOB_LOCK:
        job = _REEL_JOBS.get(job_id)
        if job:
            job.update(values, updated=time.time())

def _valid_instagram_reel_url(raw):
    try:
        parsed = urlparse(str(raw).strip())
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in {"instagram.com", "www.instagram.com", "m.instagram.com"}:
            return None
        if parsed.port not in (None, 443) or parsed.username or parsed.password:
            return None
        if not (parsed.path.startswith("/reel/") or parsed.path.startswith("/reels/")):
            return None
        return "https://www.instagram.com" + parsed.path.rstrip("/") + "/"
    except Exception:
        return None

def _safe_reel_filename(title, extension):
    base = os.path.basename(str(title or "Instagram Reel"))
    base = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', " ", base)
    base = re.sub(r"\s+", " ", base).strip(" .")[:130] or "Instagram Reel"
    ext = re.sub(r"[^a-z0-9]", "", str(extension or "mp4").lower())[:8] or "mp4"
    return base + "." + ext

def _store_downloaded_reel(path, filename, job_id):
    size = os.path.getsize(path)
    if size <= 0 or size > _REEL_MAX_BYTES:
        raise RuntimeError("The downloaded video is empty or exceeds the 500 MB limit.")
    mime = mimetypes.guess_type(filename)[0] or "video/mp4"
    fid = secrets.token_hex(6)
    n = max(1, (size + V.CHUNK - 1) // V.CHUNK)
    meta = {"name": filename, "folder": "Reels", "type": mime, "size": size,
            "t": int(time.time() * 1000)}
    created_ids = []
    response = V.dc("POST", f"/channels/{V.CH}/messages",
                    data={"content": f"v1 {fid} m {n}"},
                    files={"files[0]": (f"m{fid}.bin", seal(json.dumps(meta).encode()))})
    created_ids.append(response.json().get("id"))
    with SCAN_LOCK:
        SCAN_FOUND[fid] = {"meta": response.json()["attachments"][0]["url"],
                           "chunks": {}, "n": n, "message_ids": list(created_ids)}
        META_CACHE[fid] = {"id": fid, "name": filename, "folder": "Reels",
                           "type": mime, "size": size, "t": meta["t"]}
    try:
        sent = 0
        with open(path, "rb") as source:
            for index in range(n):
                chunk = source.read(V.CHUNK)
                if not chunk:
                    raise RuntimeError("The temporary video file ended unexpectedly.")
                response = V.dc("POST", f"/channels/{V.CH}/messages",
                                data={"content": f"v1 {fid} c{index} {n}"},
                                files={"files[0]": (f"{fid}.{index}.bin", seal(chunk))})
                message = response.json()
                created_ids.append(message.get("id"))
                with SCAN_LOCK:
                    if fid in SCAN_FOUND:
                        SCAN_FOUND[fid]["chunks"][index] = message["attachments"][0]["url"]
                        SCAN_FOUND[fid]["message_ids"].append(message.get("id"))
                sent += len(chunk)
                _reel_job_update(job_id, status="storing", percent=80 + int(20 * sent / size),
                                 message=f"Sending to Discord · {index + 1}/{n} parts")
        with _lock:
            LIB.update(t=0, items=[])
        return fid
    except Exception:
        for message_id in created_ids:
            if message_id:
                try:
                    V.dc("DELETE", f"/channels/{V.CH}/messages/{message_id}")
                except Exception:
                    pass
        with SCAN_LOCK:
            SCAN_FOUND.pop(fid, None)
            META_CACHE.pop(fid, None)
        raise

def _run_reel_jobs(job_ids):
    try:
        import yt_dlp
    except Exception as exc:
        for job_id in job_ids:
            _reel_job_update(job_id, status="failed", message="Server downloader is unavailable. Check the yt-dlp installation.")
        return
    for job_id in job_ids:
        with _REEL_JOB_LOCK:
            job = dict(_REEL_JOBS.get(job_id) or {})
        if not job:
            continue
        temp_dir = tempfile.mkdtemp(prefix="vault-reel-")
        try:
            _reel_job_update(job_id, status="downloading", percent=0, message="Connecting to Instagram…")
            def progress(data):
                if data.get("status") == "downloading":
                    total = data.get("total_bytes") or data.get("total_bytes_estimate") or 0
                    downloaded = data.get("downloaded_bytes") or 0
                    percent = min(79, int(downloaded * 79 / total)) if total else 1
                    _reel_job_update(job_id, percent=percent,
                                     message="Downloading from Instagram · " + (str(data.get("_percent_str", "")).strip() or "working"))
                elif data.get("status") == "finished":
                    _reel_job_update(job_id, percent=79, message="Download complete · preparing Discord transfer…")
            options = {
                "format": "best[ext=mp4]/best",
                "outtmpl": os.path.join(temp_dir, "%(id)s.%(ext)s"),
                "noplaylist": True, "quiet": True, "no_warnings": True,
                "restrictfilenames": True, "socket_timeout": 30,
                "retries": 2, "fragment_retries": 2, "extractor_retries": 2,
                "max_filesize": _REEL_MAX_BYTES, "progress_hooks": [progress],
            }
            with yt_dlp.YoutubeDL(options) as downloader:
                info = downloader.extract_info(job["url"], download=True)
                if not info:
                    raise RuntimeError("Instagram did not provide a downloadable video.")
                filepath = downloader.prepare_filename(info)
            if not os.path.isfile(filepath):
                candidates = [os.path.join(temp_dir, name) for name in os.listdir(temp_dir)]
                candidates = [p for p in candidates if os.path.isfile(p)]
                if not candidates:
                    raise RuntimeError("The downloaded video file was not found.")
                filepath = candidates[0]
            filename = _safe_reel_filename(info.get("title") or info.get("id"), os.path.splitext(filepath)[1].lstrip("."))
            _reel_job_update(job_id, status="storing", percent=80, title=filename,
                             message="Encrypting and sending video to Discord…")
            fid = _store_downloaded_reel(filepath, filename, job_id)
            _reel_job_update(job_id, status="completed", percent=100, file_id=fid,
                             title=filename, message="Saved in your Discord Vault · Reels")
        except Exception as exc:
            message = str(exc).strip() or "Download failed."
            if "private" in message.lower() or "login" in message.lower() or "sign in" in message.lower():
                message = "This Reel is not publicly downloadable. Private/login-required links aren't supported."
            _reel_job_update(job_id, status="failed", message=message[:240])
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/api/reels/download")
def reels_download():
    if not authed():
        abort(403)
    data = request.get_json(silent=True) or {}
    raw_urls = data.get("urls") or []
    if not isinstance(raw_urls, list):
        return "Send a list of Instagram Reel URLs.", 400
    urls = []
    for raw in raw_urls:
        url = _valid_instagram_reel_url(raw)
        if not url:
            return "Only public Instagram Reel links (instagram.com/reel/…) are accepted.", 400
        if url not in urls:
            urls.append(url)
    if not urls:
        return "Paste at least one Instagram Reel link.", 400
    job_ids = []
    now = time.time()
    with _REEL_JOB_LOCK:
        active = sum(1 for item in _REEL_JOBS.values() if item.get("status") in {"queued", "downloading", "storing"})
        for url in urls:
            job_id = secrets.token_hex(8)
            _REEL_JOBS[job_id] = {"id": job_id, "url": url, "status": "queued", "percent": 0,
                                  "message": "Waiting in server queue…", "title": "Instagram Reel",
                                  "created": now, "updated": now}
            job_ids.append(job_id)
    for job_id in job_ids:
        _REEL_EXECUTOR.submit(_run_reel_jobs, [job_id])
    return jsonify(jobs=[_REEL_JOBS[job_id] for job_id in job_ids])

@app.get("/api/reels/jobs")
def reels_jobs():
    if not authed():
        abort(403)
    with _REEL_JOB_LOCK:
        jobs = sorted(_REEL_JOBS.values(), key=lambda item: item.get("created", 0), reverse=True)[:50]
        return jsonify(jobs=jobs)

def authed():
    tok = V.KEY["token"]
    return bool(tok) and secrets.compare_digest(request.args.get("t", "").encode(), tok.encode())

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
    aes = AESGCM(PBKDF2HMAC(SHA256(), 32, b"vault-v1", 300000).derive(pw.encode()))
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
    V.KEY["aes"], V.KEY["token"] = aes, secrets.token_urlsafe(24)
    with _lock:
        LIB.update(t=0, items=[])
    start_scan()
    return jsonify(t=V.KEY["token"])

@app.post("/api/lock")
def lock():
    if authed():
        end_session()
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
            V.dc("DELETE", f"/channels/{V.CH}/messages/{mid}")
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
