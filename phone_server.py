"""Phone interface for the encrypted Discord vault. Runs behind Render's HTTPS proxy."""
import datetime, ipaddress, json, mimetypes, os, secrets, socket, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
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

def authed():
    tok = V.KEY["token"]
    return bool(tok) and secrets.compare_digest(request.args.get("t", "").encode(), tok.encode())

def _add_messages(msgs):
    global SCAN_FOUND
    with SCAN_LOCK:
        for msg in msgs:
            p = msg.get("content", "").split()
            if len(p) < 4 or p[0] != "v1" or not msg.get("attachments"):
                continue
            try:
                n = int(p[3])
            except (TypeError, ValueError):
                continue
            fid = p[1]
            f = SCAN_FOUND.setdefault(fid, {"chunks": {}, "n": n})
            url = msg["attachments"][0]["url"]
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
        return {k: {"meta": v.get("meta"), "chunks": dict(v["chunks"]), "n": v["n"]}
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

@app.get("/api/stream/<fid>")
def stream(fid):
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
            SCAN_FOUND[fid] = {"meta": url, "chunks": {}, "n": n}
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
    except Exception:
        pass
    if i == u["n"] - 1:
        UPLOADS.pop(fid, None)
        with _lock:
            LIB.update(t=0, items=[])
    return "", 204
