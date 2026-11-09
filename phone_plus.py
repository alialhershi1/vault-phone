""""Render entry point for the upgraded Vault phone app."""
import json, os, requests, threading, time
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from flask import abort, jsonify, request
import phone_server as P
V, app = P.V, P.app


_NEWS_CACHE = {"at": 0.0, "items": []}
_NEWS_LOCK = threading.Lock()

@app.get("/api/news")
def aljazeera_news():
    now = time.time()
    with _NEWS_LOCK:
        if _NEWS_CACHE["items"] and now - _NEWS_CACHE["at"] < 90:
            return jsonify(source="Al Jazeera English", items=_NEWS_CACHE["items"], fetched_at=int(_NEWS_CACHE["at"]))
    try:
        response = requests.get(
            "https://www.aljazeera.com/xml/rss/all.xml",
            headers={"User-Agent": "VaultNewsWidget/1.0 (+https://vault-phone.onrender.com)"},
            timeout=12
        )
        response.raise_for_status()
        root = ET.fromstring(response.content)
        channel = root.find("channel")
        items = []
        if channel is not None:
            for item in channel.findall("item"):
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub_date = (item.findtext("pubDate") or "").strip()
                if not title or not link:
                    continue
                if not link.startswith("https://www.aljazeera.com/"):
                    continue
                try:
                    published = parsedate_to_datetime(pub_date).timestamp() if pub_date else 0
                except Exception:
                    published = 0
                items.append({"title": title[:240], "url": link, "published": pub_date, "timestamp": int(published)})
                if len(items) >= 8:
                    break
        if not items:
            raise RuntimeError("Al Jazeera feed returned no headlines")
        with _NEWS_LOCK:
            _NEWS_CACHE.update(at=now, items=items)
        return jsonify(source="Al Jazeera English", items=items, fetched_at=int(now))
    except Exception as exc:
        with _NEWS_LOCK:
            stale = list(_NEWS_CACHE["items"])
            fetched = int(_NEWS_CACHE["at"])
        if stale:
            return jsonify(source="Al Jazeera English", items=stale, fetched_at=fetched, stale=True)
        return jsonify(error="News feed temporarily unavailable", detail=str(exc)[:120], items=[]), 502

@app.post("/api/upload/resume")
def upload_resume():
    if not P.authed(): abort(403)
    d=request.get_json(silent=True) or {}
    found=V.scan()
    fid=None
    if d.get("id"):
        fid=str(d["id"])
        if fid not in found: return jsonify({})
    else:
        name=os.path.basename(str(d.get("name") or "").replace("\\\\","/"))[:200]
        size=int(d.get("size",-1)); best=-1
        for k,f in found.items():
            have=len(f["chunks"])
            if "meta" not in f or have>=f["n"] or have<=best: continue
            try:
                r=requests.get(f["meta"],timeout=60); r.raise_for_status()
                m=json.loads(V.unseal(r.content))
            except Exception: continue
            if m.get("name")==name and m.get("size")==size: fid,best=k,have
        if fid is None: return jsonify({})
    f=found[fid]
    if len(f["chunks"])<f["n"]: P.UPLOADS[fid]={"n":f["n"]}
    with P._lock: P.LIB.update(t=0,items=None)
    return jsonify(id=fid,n=f["n"],have=sorted(f["chunks"]),chunk=V.CHUNK)


def _background_library_cache():
    """Warm and maintain the encrypted library index without a browser session.

    The worker key is recovered from the existing durable queue database. Once
    it is available, restore the saved index (or seed it from Discord on the
    first run), finish the original full-history scan, then poll for new records.
    """
    initialized = False
    while True:
        try:
            if not initialized:
                P._load_leech_worker_key()
                aes = V.KEY.get("aes")
                if aes is not None:
                    loaded = P._load_library_cache(aes)
                    if not loaded:
                        if not P.verify(aes):
                            raise RuntimeError("Could not validate the existing vault index yet")
                        P._save_library_cache()
                    initialized = True
                    print("library cache: background warm-up started", flush=True)
            if initialized:
                P.start_scan()
                P.start_meta_fill()
        except Exception as exc:
            print("library cache background worker:", str(exc)[:180], flush=True)
        time.sleep(60)


_CACHE_THREAD = threading.Thread(target=_background_library_cache, name="vault-library-cache", daemon=True)
_CACHE_THREAD.start()

if __name__=="__main__":
    # Serve the existing Flask app and private MCP endpoint together over ASGI.
    import uvicorn
    from mcp_gateway import create_asgi_app
    asgi_app = create_asgi_app(app)
    uvicorn.run(asgi_app, host="0.0.0.0", port=int(os.environ.get("PORT","10000")), proxy_headers=True, forwarded_allow_ips="*")