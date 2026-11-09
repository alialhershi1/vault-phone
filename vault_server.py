"""Discord-backed encrypted vault helpers for the phone app.
Credentials are supplied only through Render environment variables.
"""
import os, re, time, threading, requests, json
from pathlib import Path
from collections import OrderedDict
from flask import Response, abort

API = "https://discord.com/api/v10"
# Keep vault_config.json private and out of Git. Environment variables override it.
_config_path = Path(__file__).with_name("vault_config.json")
if not _config_path.exists():
    _config_path = Path(__file__).with_name("pc_leech_config.json")
try:
    _config = json.loads(_config_path.read_text(encoding="utf-8")) if _config_path.exists() else {}
except (OSError, json.JSONDecodeError):
    _config = {}
TOKEN = os.environ.get("DISCORD_TOKEN", str(_config.get("DISCORD_TOKEN", ""))).strip()
CH = os.environ.get("DISCORD_CHANNEL", str(_config.get("DISCORD_CHANNEL", "1530905756969336872"))).strip()
if not TOKEN or not CH:
    raise RuntimeError("Set DISCORD_TOKEN in SillyDev Startup or private vault_config.json.")
S = requests.Session()
S.headers.update({"Authorization": "Bot " + TOKEN, "User-Agent": "VaultPhone/1.0"})
CHUNK = 9 * 1024 * 1024
CACHE_MAX = 50 * 1024 * 1024
KEY = {"aes": None, "raw": None}
AUTH_CHECK = lambda: False  # set by phone_server (stateless token check)
_cache, _cache_bytes = OrderedDict(), 0
_clock = threading.Lock()
_inflight = {}
_files, _flock = {}, threading.Lock()

def dc(method, path, **kw):
    # Discord rate limits channel-history pagination. Respect both the HTTP
    # Retry-After header and JSON retry_after, and allow longer cooldowns.
    errs = 0
    for attempt in range(30):
        try:
            r = S.request(method, API + path, timeout=300, **kw)
        except (requests.ConnectionError, requests.Timeout):
            errs += 1
            if errs > 4: raise
            time.sleep(2 ** errs); continue
        if r.status_code >= 500 and errs < 4:
            errs += 1; time.sleep(2 ** errs); continue
        if r.status_code == 429:
            try:
                body = r.json()
            except ValueError:
                body = {}
            delay = max(
                float(r.headers.get("Retry-After", 0) or 0),
                float(body.get("retry_after", 1) or 1)
            ) + 0.5
            time.sleep(min(delay, 90))
            continue
        r.raise_for_status()
        return r
    raise RuntimeError("Discord is still rate-limiting this vault. Wait briefly and retry.")

def scan():
    found, before = {}, None
    while True:
        params = {"limit": 100}
        if before: params["before"] = before
        msgs = dc("GET", f"/channels/{CH}/messages", params=params).json()
        for m in msgs:
            p = m.get("content", "").split()
            if len(p) < 4 or p[0] != "v1" or not m.get("attachments"): continue
            f = found.setdefault(p[1], {"chunks": {}, "n": int(p[3])})
            url = m["attachments"][0]["url"]
            if p[2] == "m": f["meta"] = url
            elif p[2].startswith("c"):
                try: f["chunks"][int(p[2][1:])] = url
                except ValueError: pass
        if len(msgs) < 100: return found
        before = msgs[-1]["id"]

def unseal(data):
    return KEY["aes"].decrypt(data[:12], data[12:], None)

def clear_stream_state():
    global _cache_bytes
    with _clock:
        _cache.clear()
        _cache_bytes = 0
    with _flock: _files.clear()

def get_info(fid, refresh=False):
    with _flock:
        hit = _files.get(fid)
        if hit and not refresh and time.time() - hit[0] < 600: return hit[1]
    f = scan().get(fid)
    if not f or "meta" not in f or len(f["chunks"]) != f["n"]: abort(404)
    r = requests.get(f["meta"], timeout=60); r.raise_for_status()
    import json
    meta = json.loads(unseal(r.content))
    info = {"chunks": f["chunks"], "n": f["n"], "size": int(meta["size"]), "type": meta.get("type") or ""}
    with _flock: _files[fid] = (time.time(), info)
    return info

def get_chunk(fid, idx):
    global _cache_bytes
    k = (fid, idx)
    with _clock:
        if k in _cache:
            _cache.move_to_end(k); return _cache[k]
        lk = _inflight.setdefault(k, threading.Lock())
    with lk:
        with _clock:
            if k in _cache:
                _cache.move_to_end(k); return _cache[k]
        data = None
        info = get_info(fid)
        url = info["chunks"].get(idx)
        mid = (info.get("chunk_message_ids") or {}).get(idx)
        for attempt in (0, 1):
            if not url and mid:
                msg = dc("GET", f"/channels/{CH}/messages/{mid}").json()
                attachments = msg.get("attachments") or []
                if attachments:
                    url = attachments[0].get("url")
                    info["chunks"][idx] = url
            if not url:
                abort(404)
            r = requests.get(url, timeout=300)
            if r.ok:
                data = unseal(r.content)
                break
            if attempt == 0 and mid:
                msg = dc("GET", f"/channels/{CH}/messages/{mid}").json()
                attachments = msg.get("attachments") or []
                url = attachments[0].get("url") if attachments else None
                info["chunks"][idx] = url
            else:
                break
        if data is None: abort(502)
        with _clock:
            _cache[k] = data; _cache_bytes += len(data)
            while _cache_bytes > CACHE_MAX and len(_cache) > 1:
                _, old = _cache.popitem(last=False); _cache_bytes -= len(old)
            _inflight.pop(k, None)
        return data

def stream(fid):
    import secrets
    if not AUTH_CHECK(): abort(403)
    info = get_info(fid)
    size = info["size"]
    if size <= 0: return Response(b"", mimetype=info["type"] or "application/octet-stream")
    start, end = 0, size - 1
    rng = __import__("flask").request.headers.get("Range", "")
    m = re.match(r"bytes=(\d*)-(\d*)$", rng)
    if m and (m.group(1) or m.group(2)):
        if not m.group(1): start = max(0, size - int(m.group(2)))
        else:
            start = int(m.group(1))
            if m.group(2): end = min(int(m.group(2)), size - 1)
    if start >= size or start > end: return Response(status=416, headers={"Content-Range": f"bytes */{size}"})
    def generate():
        pos = start
        while pos <= end:
            idx = pos // CHUNK
            data = get_chunk(fid, idx)
            off = pos - idx * CHUNK
            part = data[off:off + end - pos + 1]
            if not part: break
            yield part
            pos += len(part)
    headers = {"Accept-Ranges":"bytes", "Content-Length":str(end-start+1), "Cache-Control":"no-store"}
    if m: headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    return Response(generate(), status=206 if m else 200, mimetype=info["type"] or "application/octet-stream", headers=headers)

def request_token():
    from flask import request
    return request.args.get("t", "")
