"""Movies & Series section for PC Vault (Stremio-style browsing, Leecher hand-off, range streaming).

Self-contained and removable: delete this file and the MOVIES_SECTION block in the vault to undo it.

Design follows the Stremio *addon protocol* that stremio-core implements (catalog / meta / stream
resources over plain HTTP + JSON) - no stremio-core code is copied (it is MIT licensed, Rust, and has no UI).

Environment (all optional except LEECH_*):
  LEECH_URL               e.g. https://vault-leecher.onrender.com   (your Render Leecher)
  LEECH_KEY               the same LEECH_KEY the Leecher uses (sent as X-Key)
  STREMIO_STREAM_ADDONS   comma-separated Stremio addon base URLs that return torrent streams
                          (the manifest URL minus /manifest.json). Use only sources for content you
                          are allowed to download. None are bundled. Without any, paste a magnet manually.
  MOVIES_META_URL         metadata addon, default Cinemeta (Stremio's own, no API key needed)
"""
import json, os, re, threading, time, secrets
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests
from flask import Blueprint, Response, abort, jsonify, request, stream_with_context

META_URL = os.environ.get("MOVIES_META_URL", "https://v3-cinemeta.strem.io").rstrip("/")
LEECH_URL = os.environ.get("LEECH_URL", "").strip().rstrip("/")
LEECH_KEY = os.environ.get("LEECH_KEY", "").strip()
ADDONS = [re.sub(r"/manifest\.json$", "", a.strip().rstrip("/"))
          for a in os.environ.get("STREMIO_STREAM_ADDONS", "").split(",") if a.strip()]
TRACKERS = ["udp://tracker.opentrackr.org:1337/announce", "udp://open.tracker.cl:1337/announce",
            "udp://tracker.torrent.eu.org:451/announce", "udp://exodus.desync.com:6969/announce",
            "udp://open.stealth.si:80/announce"]
VIDEO_EXT = (".mp4", ".mkv", ".webm", ".mov", ".m4v", ".avi")
ACTIVE = ("queued", "downloading", "uploading")
UA = {"User-Agent": "PCVault-Movies/1.0"}

bp = Blueprint("movies", __name__, url_prefix="/api/movies")
C = {}                       # vault context (scan_state, unseal, ...)
_db_lock = threading.Lock()
_http_cache = {}


# ----------------------------------------------------------------------------- helpers
def _json(url, ttl=600, timeout=20):
    hit = _http_cache.get(url)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    r = requests.get(url, timeout=timeout, headers=UA)
    r.raise_for_status()
    data = r.json()
    _http_cache[url] = (time.time(), data)
    if len(_http_cache) > 400:
        for k in sorted(_http_cache, key=lambda k: _http_cache[k][0])[:100]:
            _http_cache.pop(k, None)
    return data


def _err(e, code=502):
    return jsonify(error=str(e)[:300]), code


def _fmt_size(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}" if u not in ("B",) else f"{int(n)} B"
        n /= 1024


def _card(m, t):
    genres = m.get("genres") or m.get("genre") or []
    return {"id": m.get("imdb_id") or m.get("id"), "type": t, "name": m.get("name"), "poster": m.get("poster"),
            "year": m.get("year") or (m.get("releaseInfo") or "")[:4], "rating": m.get("imdbRating"),
            "genres": genres[:3]}


# ----------------------------------------------------------------------------- metadata (catalog / meta)
@bp.get("/config")
def config():
    return jsonify(leecher=bool(LEECH_URL and LEECH_KEY), addons=len(ADDONS))


@bp.get("/catalog")
def catalog():
    t = request.args.get("type", "movie")
    if t not in ("movie", "series"):
        return _err("bad type", 400)
    cat = request.args.get("cat", "top")
    if cat not in ("top", "year", "imdbRating"):
        cat = "top"
    extra = []
    if request.args.get("search"):
        extra.append("search=" + quote(request.args["search"].strip()))
    if request.args.get("genre"):
        extra.append("genre=" + quote(request.args["genre"]))
    skip = int(request.args.get("skip", 0) or 0)
    if skip:
        extra.append(f"skip={skip}")
    url = f"{META_URL}/catalog/{t}/{cat}" + (("/" + "&".join(extra)) if extra else "") + ".json"
    try:
        metas = _json(url).get("metas", [])
    except Exception as e:
        return _err(e)
    return jsonify(items=[_card(m, t) for m in metas if m.get("name")])


@bp.get("/meta")
def meta():
    t, i = request.args.get("type", "movie"), request.args.get("id", "")
    if t not in ("movie", "series") or not re.fullmatch(r"tt\d+", i):
        return _err("bad id", 400)
    try:
        m = _json(f"{META_URL}/meta/{t}/{i}.json", ttl=1800).get("meta") or {}
    except Exception as e:
        return _err(e)
    out = _card(m, t)
    out.update(id=i, background=m.get("background"), description=m.get("description"), runtime=m.get("runtime"),
               genres=m.get("genres") or m.get("genre") or [], cast=(m.get("cast") or [])[:6])
    seasons = {}
    for v in m.get("videos") or []:
        s, ep = v.get("season"), v.get("episode")
        if s is None or ep is None:
            continue
        seasons.setdefault(int(s), []).append({
            "episode": int(ep), "id": v.get("id") or f"{i}:{s}:{ep}", "title": v.get("title") or v.get("name") or f"Episode {ep}",
            "overview": v.get("overview") or v.get("description") or "", "thumbnail": v.get("thumbnail"),
            "released": (v.get("released") or "")[:10]})
    out["seasons"] = {str(k): sorted(v, key=lambda x: x["episode"]) for k, v in
                      sorted(seasons.items(), key=lambda kv: (kv[0] == 0, kv[0]))}
    return jsonify(out)


# ----------------------------------------------------------------------------- torrent sources (Stremio stream addons)
_QRANK = ["4K", "1440p", "1080p", "720p", "480p", "?"]


def _parse_stream(s):
    title, name = s.get("title") or s.get("description") or "", s.get("name") or ""
    blob = name + "\n" + title
    q = re.search(r"(2160p|4k|uhd|1440p|1080p|720p|480p)", blob, re.I)
    quality = "?"
    if q:
        k = q.group(1).lower()
        quality = "4K" if k in ("2160p", "4k", "uhd") else k
    seeders = re.search(r"👤\s*(\d+)", blob)
    size = (s.get("behaviorHints") or {}).get("videoSize")
    size_txt = _fmt_size(size) if size else ((re.search(r"💾\s*([\d.,]+\s*[KMGT]i?B)", blob, re.I) or [None, ""])[1])
    src = re.search(r"⚙️\s*([^\n]+)", title)
    ih = (s.get("infoHash") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", ih):
        return None            # only real torrents; no debrid / direct-url streams
    dn = quote((title.split("\n")[0] or name or ih)[:120])
    tr = [x[8:] for x in (s.get("sources") or []) if isinstance(x, str) and x.startswith("tracker:")] or TRACKERS
    magnet = f"magnet:?xt=urn:btih:{ih}&dn={dn}" + "".join("&tr=" + quote(t, safe="") for t in tr[:8])
    return {"quality": quality, "size": size_txt, "seeders": int(seeders.group(1)) if seeders else None,
            "source": (src.group(1).strip() if src else name.split("\n")[0].strip()) or "torrent",
            "name": (title.split("\n")[0] or name)[:140], "magnet": magnet}


@bp.get("/sources")
def sources():
    t, i = request.args.get("type", "movie"), request.args.get("id", "")
    if t not in ("movie", "series") or not re.fullmatch(r"tt\d+(:\d+:\d+)?", i):
        return _err("bad id", 400)
    if not ADDONS:
        return jsonify(sources=[], addons=0)

    def one(base):
        try:
            return _json(f"{base}/stream/{t}/{quote(i, safe=':')}.json", ttl=300, timeout=25).get("streams", [])
        except Exception:
            return []
    with ThreadPoolExecutor(max_workers=min(6, len(ADDONS))) as ex:
        raw = [s for part in ex.map(one, ADDONS) for s in part]
    seen, out = set(), []
    for s in raw:
        p = _parse_stream(s)
        if p and p["magnet"] not in seen:
            seen.add(p["magnet"])
            out.append(p)
    out.sort(key=lambda x: (_QRANK.index(x["quality"]), -(x["seeders"] or 0)))
    return jsonify(sources=out[:40], addons=len(ADDONS))


# ----------------------------------------------------------------------------- library store
def _db_path():
    return Path(C["__file__"]).with_name(".vault_movies.json")


def _load():
    try:
        return json.loads(_db_path().read_text("utf-8"))
    except Exception:
        return {}


def _save(d):
    p = _db_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(d), "utf-8")
    os.replace(tmp, p)


# ----------------------------------------------------------------------------- Leecher client (isolated)
def _leech(method, path, **kw):
    if not (LEECH_URL and LEECH_KEY):
        raise RuntimeError("Set LEECH_URL and LEECH_KEY first.")
    r = requests.request(method, LEECH_URL + path, headers={"X-Key": LEECH_KEY, **UA}, timeout=40, **kw)
    if r.status_code == 401:
        raise RuntimeError("Leecher rejected LEECH_KEY.")
    r.raise_for_status()
    return r


def _pick(files, item):
    vids = [f for f in files if f["name"].lower().endswith(VIDEO_EXT)]
    vids = [f for f in vids if not re.search(r"sample", f["name"], re.I)] or vids
    pat = None
    if item["type"] == "series" and item.get("season") is not None:
        s, e = item["season"], item["episode"]
        pat = re.compile(rf"(s0*{s}[ ._-]*e0*{e}(?!\d)|\b{s}x0*{e}(?!\d))", re.I)
        hit = [f for f in vids if pat.search(f["name"])]
        vids = hit or vids
    main = max(vids, key=lambda f: f.get("size") or 0) if vids else None
    subs = [f for f in files if f["name"].lower().endswith(".srt") and (not pat or pat.search(f["name"]) or len(files) < 4)]
    return main, subs[:6]


def _sync():
    with _db_lock:
        d = _load()
        act = [k for k, v in d.items() if v.get("status") in ACTIVE]
        if not act or not (LEECH_URL and LEECH_KEY):
            return d
        try:
            live = {j["id"]: j for j in _leech("GET", "/api/jobs").json()}
        except Exception as e:
            for k in act:
                d[k]["warn"] = str(e)[:140]
            return d
        changed = False
        for k in act:
            it, j = d[k], live.get(d[k]["leech_id"])
            it.pop("warn", None)
            if not j:
                it["status"], it["error"] = "lost", "Leecher no longer knows this job (it may have restarted)."
                changed = True
                continue
            it.update(status=j["status"], pct=j.get("pct") or 0, speed=j.get("speed") or "", eta=j.get("eta") or "",
                      error=j.get("error") or "")
            if j["status"] == "done":
                main, subs = _pick(j.get("fids") or [], it)
                if main:
                    it.update(fid=main["fid"], file=main["name"], size=main.get("size"), pct=100, error="",
                              subs=[{"fid": s["fid"], "name": s["name"]} for s in subs])
                    try:
                        C["kick_scan"](force=True)      # make the new Discord file visible to the vault
                    except Exception:
                        pass
                else:
                    it["status"], it["error"] = "error", "Finished, but no playable video file was reported (is the Leecher updated?)."
            changed = True
        if changed:
            _save(d)
        return d


@bp.get("/library")
def library():
    d = _sync()
    return jsonify(items=sorted(d.values(), key=lambda x: -x.get("created", 0)))


@bp.post("/download")
def download():
    b = request.get_json(silent=True) or {}
    magnet = str(b.get("magnet", "")).strip()
    t, imdb = b.get("type"), str(b.get("id", ""))
    if not (magnet.startswith("magnet:?") or re.match(r"https?://", magnet)):
        return _err("Need a magnet link.", 400)
    if t not in ("movie", "series") or not re.fullmatch(r"tt\d+", imdb):
        return _err("bad item", 400)
    season = int(b["season"]) if b.get("season") is not None else None
    episode = int(b["episode"]) if b.get("episode") is not None else None
    with _db_lock:
        d = _load()
        for v in d.values():
            if (v["imdb"], v.get("season"), v.get("episode")) == (imdb, season, episode) and v["status"] in ACTIVE + ("done",):
                return _err("Already downloading or in your library.", 409)
    try:
        j = _leech("POST", "/api/add", json={"link": magnet}).json()
    except Exception as e:
        return _err(e)
    key = secrets.token_hex(5)
    item = {"key": key, "leech_id": j["id"], "type": t, "imdb": imdb, "season": season, "episode": episode,
            "title": str(b.get("title", ""))[:200], "poster": b.get("poster"), "quality": b.get("quality"),
            "status": j.get("status", "queued"), "pct": 0, "created": int(time.time()), "fid": None}
    with _db_lock:
        d = _load()
        d[key] = item
        _save(d)
    return jsonify(item)


@bp.post("/cancel/<key>")
def cancel(key):
    with _db_lock:
        it = _load().get(key)
    if not it:
        abort(404)
    try:
        _leech("POST", f"/api/cancel/{it['leech_id']}")
    except Exception as e:
        return _err(e)
    return "", 204


@bp.delete("/library/<key>")
def remove(key):
    """Removes the entry from this section only. The encrypted file stays in the vault (delete it in Library)."""
    with _db_lock:
        d = _load()
        d.pop(key, None)
        _save(d)
    return "", 204


# ----------------------------------------------------------------------------- streaming (HTTP Range, chunked, RAM-capped)
CACHE_MAX = 72 * 1024 * 1024
_cache, _cbytes = OrderedDict(), 0
_clock, _infl = threading.Lock(), {}
_info_cache = {}


def _found(fid, refresh=False):
    if refresh:
        C["kick_scan"](force=True)
        time.sleep(0.6)
        for _ in range(60):
            if C["scan_state"].get("status") in ("ready", "error"):
                break
            time.sleep(0.5)
    else:
        C["kick_scan"]()
    for _ in range(40):
        with C["scan_lock"]:
            f = (C["scan_state"].get("found") or {}).get(fid)
        if f and f.get("meta") and len(f["chunks"]) == f["n"]:
            return f
        time.sleep(0.4)
    return None


def _info(fid):
    hit = _info_cache.get(fid)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    f = _found(fid)
    if not f:
        abort(404)
    m = requests.get(f["meta"], timeout=60)
    m.raise_for_status()
    meta_ = json.loads(C["unseal"](m.content))
    info = {"size": int(meta_["size"]), "name": meta_.get("name", ""), "n": f["n"],
            "type": meta_.get("type") or "application/octet-stream"}
    _info_cache[fid] = (time.time(), info)
    return info


def _chunk(fid, idx):
    global _cbytes
    k = (fid, idx)
    with _clock:
        if k in _cache:
            _cache.move_to_end(k)
            return _cache[k]
        lk = _infl.setdefault(k, threading.Lock())
    with lk:
        with _clock:
            if k in _cache:
                _cache.move_to_end(k)
                return _cache[k]
        data = None
        for attempt in (0, 1):               # 2nd try re-scans Discord for fresh CDN links
            f = _found(fid, refresh=bool(attempt))
            if not f:
                break
            try:
                r = requests.get(f["chunks"][idx], timeout=180)
                if r.ok:
                    data = C["unseal"](r.content)
                    break
            except requests.RequestException:
                pass
        if data is None:
            raise RuntimeError("Discord download failed")
        with _clock:
            _cache[k] = data
            _cbytes += len(data)
            while _cbytes > CACHE_MAX and len(_cache) > 1:
                _, old = _cache.popitem(last=False)
                _cbytes -= len(old)
            _infl.pop(k, None)
        return data


def _prefetch(fid, idx, n):
    if idx < n:
        try:
            _chunk(fid, idx)
        except Exception:
            pass


@bp.route("/stream/<fid>", methods=["GET", "HEAD"])
def stream(fid):
    if not re.fullmatch(r"[0-9a-f]{12}", fid):
        abort(400)
    info = _info(fid)
    size, n, CH = info["size"], info["n"], C["CHUNK"]
    start, end = 0, size - 1
    m = re.match(r"bytes=(\d*)-(\d*)$", request.headers.get("Range", ""))
    if m and (m.group(1) or m.group(2)):
        if m.group(1) == "":
            start = max(0, size - int(m.group(2)))
        else:
            start = int(m.group(1))
            if m.group(2):
                end = min(int(m.group(2)), size - 1)
    if start >= size or start > end:
        return Response(status=416, headers={"Content-Range": f"bytes */{size}"})

    def gen():
        pos = start
        while pos <= end:
            idx = pos // CH
            threading.Thread(target=_prefetch, args=(fid, idx + 1, n), daemon=True).start()
            data = _chunk(fid, idx)
            off = pos - idx * CH
            piece = data[off:off + (end - pos + 1)]
            yield piece
            pos += len(piece)

    mime = info["type"]
    if info["name"].lower().endswith(".mkv"):
        mime = "video/x-matroska"
    h = {"Accept-Ranges": "bytes", "Content-Length": str(end - start + 1), "Cache-Control": "no-store"}
    if m:
        h["Content-Range"] = f"bytes {start}-{end}/{size}"
    body = b"" if request.method == "HEAD" else stream_with_context(gen())
    return Response(body, status=206 if m else 200, mimetype=mime, headers=h)


@bp.get("/subs/<fid>")
def subs(fid):
    if not re.fullmatch(r"[0-9a-f]{12}", fid):
        abort(400)
    info = _info(fid)
    if info["size"] > 3_000_000:
        abort(413)
    raw = b"".join(_chunk(fid, i) for i in range(info["n"]))
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    text = re.sub(r"(\d+:\d+:\d+),(\d+)", r"\1.\2", text.replace("\r\n", "\n"))
    return Response("WEBVTT\n\n" + text, mimetype="text/vtt; charset=utf-8")


# ----------------------------------------------------------------------------- UI (CSS + HTML + JS injected into the vault page)
_CSS = r"""
<style id="mv-style">
#sec-movies{--mv-r:12px}
.mv-top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.mv-nav{display:flex;gap:6px;flex-wrap:wrap}
.mv-nav button,.mv-chip{background:var(--panel);color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:7px 14px;font:inherit;font-size:13px;cursor:pointer;transition:.15s}
.mv-nav button:hover,.mv-chip:hover{color:var(--text);border-color:var(--accent)}
.mv-nav button.on,.mv-chip.on{background:var(--accent);color:#fff;border-color:var(--accent)}
#mv-q{flex:1;min-width:180px;max-width:360px;margin-left:auto}
.mv-chips{display:flex;gap:6px;overflow-x:auto;padding-bottom:8px;margin-bottom:10px;scrollbar-width:thin}
.mv-chip{white-space:nowrap;padding:5px 12px}
.mv-row{margin:0 0 22px}.mv-row h3{margin:0 0 10px;font-size:17px}
.mv-scroll{display:flex;gap:14px;overflow-x:auto;padding:4px 2px 12px;scroll-snap-type:x proximity;scrollbar-width:thin}
.mv-scroll .mv-card{flex:0 0 148px;scroll-snap-align:start}
.mv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:16px}
.mv-card{cursor:pointer;min-width:0}
.mv-poster{position:relative;aspect-ratio:2/3;border-radius:var(--mv-r);overflow:hidden;background:var(--panel2);border:1px solid var(--line);transition:transform .18s,box-shadow .18s}
.mv-card:hover .mv-poster{transform:translateY(-4px) scale(1.03);box-shadow:0 12px 28px rgba(0,0,0,.55);border-color:var(--accent)}
.mv-poster img{width:100%;height:100%;object-fit:cover;display:block}
.mv-noposter{display:flex;align-items:center;justify-content:center;height:100%;padding:10px;text-align:center;color:var(--muted);font-size:13px}
.mv-rate{position:absolute;top:7px;left:7px;background:rgba(0,0,0,.72);color:#ffd166;font-size:11px;font-weight:700;padding:3px 7px;border-radius:999px}
.mv-badge{position:absolute;bottom:7px;right:7px;background:var(--accent);color:#fff;font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px}
.mv-bar-in{position:absolute;left:0;right:0;bottom:0;height:5px;background:rgba(0,0,0,.6)}.mv-bar-in i{display:block;height:100%;background:var(--accent)}
.mv-t{margin-top:8px;font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mv-s{font-size:12px;color:var(--muted)}
.mv-skel{background:linear-gradient(100deg,var(--panel) 30%,var(--panel2) 50%,var(--panel) 70%);background-size:300% 100%;animation:mvsh 1.2s infinite linear;border-radius:var(--mv-r);aspect-ratio:2/3;flex:0 0 148px}
.mv-skel.h{aspect-ratio:auto;height:320px;flex:1}
@keyframes mvsh{to{background-position:-100% 0}}
.mv-hero{position:relative;border-radius:16px;overflow:hidden;border:1px solid var(--line);background:var(--panel)}
.mv-hero-bg{position:absolute;inset:0;background-size:cover;background-position:center top;opacity:.38;filter:saturate(1.1)}
.mv-hero:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,var(--bg) 8%,rgba(11,15,20,.55) 60%,rgba(11,15,20,.2))}
.mv-hero-in{position:relative;z-index:1;display:flex;gap:24px;padding:26px;flex-wrap:wrap}
.mv-hero-poster{width:200px;aspect-ratio:2/3;border-radius:12px;object-fit:cover;box-shadow:0 14px 40px rgba(0,0,0,.6);background:var(--panel2)}
.mv-hero-txt{flex:1;min-width:260px}
.mv-hero-txt h2{margin:0 0 6px;font-size:30px;line-height:1.15}
.mv-meta{color:var(--muted);font-size:14px;margin-bottom:10px}.mv-meta b{color:#ffd166}
.mv-gen{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}.mv-gen span{border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:12px;color:var(--muted)}
.mv-desc{max-width:720px;line-height:1.55;margin-bottom:16px}
.mv-acts{display:flex;gap:10px;flex-wrap:wrap}
.mv-btn{background:var(--accent);color:#fff;border:0;border-radius:10px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer}.mv-btn:hover{background:var(--accent2)}
.mv-btn.s{background:var(--panel2);color:var(--text);border:1px solid var(--line)}.mv-btn.sm{padding:6px 12px;font-size:13px}
.mv-back{background:none;border:0;color:var(--muted);cursor:pointer;font:inherit;margin-bottom:10px}.mv-back:hover{color:var(--text)}
.mv-eps{margin-top:18px}.mv-ep{display:flex;gap:12px;align-items:center;padding:10px;border:1px solid var(--line);border-radius:10px;background:var(--panel);margin-bottom:8px}
.mv-ep img,.mv-ep .ph{width:120px;aspect-ratio:16/9;object-fit:cover;border-radius:8px;background:var(--panel2);flex:0 0 120px}
.mv-ep .tx{flex:1;min-width:0}.mv-ep .tx b{display:block}.mv-ep .tx small{color:var(--muted);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.mv-dl{margin-bottom:16px}.mv-dli{display:flex;gap:12px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:9px 12px;margin-bottom:6px;font-size:13px}
.mv-dli .bar{flex:1;height:6px;background:var(--line);border-radius:3px;overflow:hidden}.mv-dli .bar i{display:block;height:100%;background:var(--accent)}
.mv-note{background:var(--panel);border:1px dashed var(--line);border-radius:10px;padding:12px 14px;color:var(--muted);font-size:13px;margin-bottom:14px}
.mv-ov{position:fixed;inset:0;background:rgba(5,8,12,.82);z-index:9000;display:none;align-items:center;justify-content:center;padding:18px}.mv-ov.on{display:flex}
.mv-box{background:var(--panel);border:1px solid var(--line);border-radius:16px;width:min(720px,100%);max-height:88vh;overflow:auto;padding:20px}
.mv-src{display:flex;gap:12px;align-items:center;padding:10px;border:1px solid var(--line);border-radius:10px;margin-bottom:8px;background:var(--panel2)}
.mv-q{font-weight:800;font-size:12px;background:var(--accent-soft);color:var(--accent);border-radius:6px;padding:4px 8px;min-width:46px;text-align:center}
.mv-src .tx{flex:1;min-width:0;font-size:13px}.mv-src .tx b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.mv-src .tx small{color:var(--muted)}
#mv-player{background:#000;padding:0;flex-direction:column}
#mv-player video{width:100%;height:100%;max-height:100vh;background:#000}
#mv-pbar{position:absolute;top:0;left:0;right:0;display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:linear-gradient(#000a,transparent);color:#fff;z-index:2}
</style>
"""

_HTML = r"""
<section id="sec-movies" class="section">
  <div class="mv-top">
    <div class="mv-nav" id="mv-nav">
      <button data-v="home" class="on">Home</button><button data-v="movie">Movies</button>
      <button data-v="series">Series</button><button data-v="lib">My Library</button>
    </div>
    <input type="text" id="mv-q" placeholder="Search movies &amp; series…" autocomplete="off">
  </div>
  <div id="mv-dl" class="mv-dl"></div>
  <div id="mv-view"></div>
</section>
"""

_JS = r"""
<div class="mv-ov" id="mv-modal"><div class="mv-box" id="mv-modal-box"></div></div>
<div class="mv-ov" id="mv-player"><div id="mv-pbar"><b id="mv-ptitle"></b><button class="mv-btn s sm" id="mv-pclose">✕ Close</button></div><video id="mv-video" controls playsinline></video></div>
<script>
(function(){
const MV={view:'home',type:'movie',genre:'',q:'',cfg:{},lib:[],inited:false,skip:0,ctx:null,t:0};
const GENRES=['Action','Adventure','Animation','Comedy','Crime','Documentary','Drama','Fantasy','Horror','Mystery','Sci-Fi','Thriller','Family','Romance','Western'];
const GMAP={'Sci-Fi':'Sci-Fi'};
const $=s=>document.querySelector(s), V=()=>$('#mv-view');
const e=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function jget(u){const r=await fetch(u);const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||('Error '+r.status));return d}
async function jpost(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||('Error '+r.status));return d}
const prog=()=>{try{return JSON.parse(localStorage.getItem('mv_prog')||'{}')}catch(_){return{}}};
const setProg=(fid,t,d)=>{try{const p=prog();p[fid]={t,d,at:Date.now()};localStorage.setItem('mv_prog',JSON.stringify(p))}catch(_){}};
const libFor=(id,s,ep)=>MV.lib.find(x=>x.imdb===id&&(x.season??null)===(s??null)&&(x.episode??null)===(ep??null));
const skel=(n,h)=>Array.from({length:n},()=>'<div class="mv-skel'+(h?' h':'')+'"></div>').join('');

function card(m){
  return `<div class="mv-card" data-t="${m.type}" data-id="${e(m.id)}"><div class="mv-poster">${m.poster?`<img loading="lazy" src="${e(m.poster)}" alt="" onerror="this.style.display='none'">`:`<div class="mv-noposter">${e(m.name)}</div>`}${m.rating?`<span class="mv-rate">★ ${e(m.rating)}</span>`:''}</div><div class="mv-t" title="${e(m.name)}">${e(m.name)}</div><div class="mv-s">${e(m.year)}${m.genres&&m.genres.length?' · '+e(m.genres[0]):''}</div></div>`;
}
function libCard(it){
  const p=it.fid?prog()[it.fid]:null, pc=p&&p.d?Math.min(100,100*p.t/p.d):0;
  const label=it.type==='series'?`${e(it.title)} · S${it.season}E${it.episode}`:e(it.title);
  return `<div class="mv-card" data-lib="${e(it.key)}"><div class="mv-poster">${it.poster?`<img loading="lazy" src="${e(it.poster)}" alt="">`:`<div class="mv-noposter">${e(it.title)}</div>`}${it.status==='done'?'<span class="mv-badge">▶ Play</span>':`<span class="mv-badge">${e(it.status)} ${it.pct||0}%</span>`}${pc>2?`<div class="mv-bar-in"><i style="width:${pc}%"></i></div>`:''}</div><div class="mv-t" title="${label}">${label}</div><div class="mv-s">${e(it.quality||'')}</div></div>`;
}
function row(title,id,body){return `<section class="mv-row"><h3>${e(title)}</h3><div class="mv-scroll" id="${id}">${body}</div></section>`}
function setNav(v){document.querySelectorAll('#mv-nav button').forEach(b=>b.classList.toggle('on',b.dataset.v===v))}

async function home(){
  MV.view='home';setNav('home');
  const rows=[['Popular movies','movie','top'],['Popular series','series','top'],['New movies','movie','year'],['New series','series','year']];
  const cont=MV.lib.filter(x=>x.status==='done'&&x.fid&&prog()[x.fid]&&prog()[x.fid].d&&(prog()[x.fid].t/prog()[x.fid].d)>.02&&(prog()[x.fid].t/prog()[x.fid].d)<.95);
  let h='';
  if(cont.length)h+=row('Continue watching','mv-r-cont',cont.map(libCard).join(''));
  const ready=MV.lib.filter(x=>x.status==='done'&&x.fid);
  if(ready.length)h+=row('In your vault','mv-r-lib',ready.map(libCard).join(''));
  rows.forEach((r,i)=>h+=row(r[0],'mv-r'+i,skel(8)));
  V().innerHTML=h;
  rows.forEach(async(r,i)=>{try{const d=await jget(`/api/movies/catalog?type=${r[1]}&cat=${r[2]}`);const el=$('#mv-r'+i);if(el&&MV.view==='home')el.innerHTML=d.items.map(card).join('')||'<div class="mv-s">Nothing here.</div>'}catch(x){const el=$('#mv-r'+i);if(el)el.innerHTML='<div class="mv-note">'+e(x.message)+'</div>'}});
}
async function browse(type,more){
  MV.view=type;setNav(type);
  if(!more){MV.skip=0;V().innerHTML=`<div class="mv-chips"><button class="mv-chip${MV.genre?'':' on'}" data-g="">All</button>${GENRES.map(g=>`<button class="mv-chip${MV.genre===g?' on':''}" data-g="${g}">${g}</button>`).join('')}</div><div class="mv-grid" id="mv-g">${skel(12)}</div><div style="text-align:center;margin:18px"><button class="mv-btn s" id="mv-more" style="display:none">Load more</button></div>`}
  try{
    const d=await jget(`/api/movies/catalog?type=${type}&cat=top${MV.genre?'&genre='+encodeURIComponent(MV.genre):''}&skip=${MV.skip}`);
    if(MV.view!==type)return;const g=$('#mv-g');if(!g)return;
    if(!more)g.innerHTML='';g.insertAdjacentHTML('beforeend',d.items.map(card).join(''));
    MV.skip+=d.items.length;const mb=$('#mv-more');if(mb)mb.style.display=d.items.length?'':'none';
    if(!g.children.length)g.innerHTML='<div class="mv-note">No results.</div>';
  }catch(x){const g=$('#mv-g');if(g)g.innerHTML='<div class="mv-note">'+e(x.message)+'</div>'}
}
async function search(q){
  MV.view='search';setNav('');
  V().innerHTML=row('Movies','mv-sm',skel(8))+row('Series','mv-ss',skel(8));
  for(const [t,id] of [['movie','mv-sm'],['series','mv-ss']]){
    jget(`/api/movies/catalog?type=${t}&search=${encodeURIComponent(q)}`).then(d=>{if(MV.view!=='search')return;$('#'+id).innerHTML=d.items.map(card).join('')||'<div class="mv-s">No results.</div>'}).catch(x=>{const el=$('#'+id);if(el)el.innerHTML='<div class="mv-note">'+e(x.message)+'</div>'});
  }
}
function library(){
  MV.view='lib';setNav('lib');
  V().innerHTML=MV.lib.length?`<div class="mv-grid">${MV.lib.map(libCard).join('')}</div>`:'<div class="mv-note">Nothing yet. Open a movie, pick a source and it will appear here once the Leecher has put it in your vault.</div>';
}

async function detail(type,id){
  MV.view='detail';setNav('');V().innerHTML='<button class="mv-back" data-act="back">← Back</button><div class="mv-hero" style="min-height:340px;padding:26px"><div class="mv-skel h"></div></div>';
  let m;try{m=await jget(`/api/movies/meta?type=${type}&id=${encodeURIComponent(id)}`)}catch(x){V().innerHTML='<button class="mv-back" data-act="back">← Back</button><div class="mv-note">'+e(x.message)+'</div>';return}
  MV.cur=m;
  const it=type==='movie'?libFor(id,null,null):null;
  const acts=type==='movie'?`${it&&it.status==='done'?`<button class="mv-btn" data-play="${e(it.key)}">▶ Play</button>`:''}${it&&ACTIVE(it)?`<button class="mv-btn s" disabled>${e(it.status)} ${it.pct||0}%</button>`:`<button class="mv-btn${it&&it.status==='done'?' s':''}" data-src="${e(id)}">⬇ Find sources</button>`}`:'';
  const seasons=Object.keys(m.seasons||{}).sort((a,b)=>(a==='0')-(b==='0')||a-b);
  V().innerHTML=`<button class="mv-back" data-act="back">← Back</button><div class="mv-hero"><div class="mv-hero-bg" style="background-image:url('${e(m.background||m.poster||'')}')"></div><div class="mv-hero-in">${m.poster?`<img class="mv-hero-poster" src="${e(m.poster)}" alt="">`:''}<div class="mv-hero-txt"><h2>${e(m.name)}</h2><div class="mv-meta">${[e(m.year),e(m.runtime),m.rating?'<b>★ '+e(m.rating)+'</b>':''].filter(Boolean).join(' · ')}</div><div class="mv-gen">${(m.genres||[]).map(g=>'<span>'+e(g)+'</span>').join('')}</div><div class="mv-desc">${e(m.description||'No description available.')}</div><div class="mv-acts">${acts}</div></div></div></div>${type==='series'?`<div class="mv-eps"><div class="mv-acts" style="margin-bottom:12px"><select id="mv-season">${seasons.map(s=>`<option value="${s}">${s==='0'?'Specials':'Season '+s}</option>`).join('')}</select></div><div id="mv-eplist"></div></div>`:''}`;
  if(type==='series'&&seasons.length){const first=seasons.find(s=>s!=='0')||seasons[0];$('#mv-season').value=first;eps(first)}
}
const ACTIVE=it=>['queued','downloading','uploading'].includes(it.status);
function eps(s){
  const m=MV.cur;if(!m)return;
  $('#mv-eplist').innerHTML=(m.seasons[s]||[]).map(ep=>{
    const it=libFor(m.id,+s,ep.episode);
    const btn=it&&it.status==='done'?`<button class="mv-btn sm" data-play="${e(it.key)}">▶ Play</button>`:it&&ACTIVE(it)?`<button class="mv-btn s sm" disabled>${e(it.status)} ${it.pct||0}%</button>`:`<button class="mv-btn s sm" data-src="${e(m.id)}" data-s="${s}" data-e="${ep.episode}">⬇ Sources</button>`;
    return `<div class="mv-ep">${ep.thumbnail?`<img loading="lazy" src="${e(ep.thumbnail)}" alt="">`:'<div class="ph"></div>'}<div class="tx"><b>${ep.episode}. ${e(ep.title)}</b><small>${e(ep.overview)}</small><small>${e(ep.released)}</small></div>${btn}</div>`}).join('')||'<div class="mv-s">No episodes listed.</div>';
}

/* ---- sources modal: nothing is downloaded until you press Download on a row ---- */
async function sources(imdb,s,ep){
  const m=MV.cur,sid=s!=null?`${imdb}:${s}:${ep}`:imdb,label=m.name+(s!=null?` · S${s}E${ep}`:'');
  MV.ctx={type:m.type,id:imdb,season:s,episode:ep,title:m.name,poster:m.poster};
  const box=$('#mv-modal-box');$('#mv-modal').classList.add('on');
  box.innerHTML=`<h3 style="margin:0 0 4px">${e(label)}</h3><div class="mv-s" style="margin-bottom:12px">Pick a source to send to your Leecher.</div><div id="mv-srcs">${skel(3,true).replace(/class="mv-skel h"/g,'class="mv-skel h" style="height:54px;margin-bottom:8px"')}</div><div style="margin-top:14px"><div class="mv-s" style="margin-bottom:6px">Or paste a magnet link</div><div class="mv-acts"><input type="text" id="mv-mag" placeholder="magnet:?xt=urn:btih:…" style="flex:1"><button class="mv-btn sm" id="mv-magb">Download</button></div></div><div style="text-align:right;margin-top:14px"><button class="mv-btn s sm" data-act="close">Close</button></div>`;
  try{
    const d=await jget(`/api/movies/sources?type=${m.type}&id=${encodeURIComponent(sid)}`);const el=$('#mv-srcs');if(!el)return;
    el.innerHTML=d.sources.length?d.sources.map((x,i)=>`<div class="mv-src"><span class="mv-q">${e(x.quality)}</span><div class="tx"><b title="${e(x.name)}">${e(x.name)}</b><small>${[x.size,x.seeders!=null?x.seeders+' seeders':'',x.source].filter(Boolean).map(e).join(' · ')}</small></div><button class="mv-btn sm" data-dl="${i}">Download</button></div>`).join(''):`<div class="mv-note">${d.addons?'No sources found for this title.':'No source addon configured (STREMIO_STREAM_ADDONS). You can still paste a magnet below.'}</div>`;
    MV.srcs=d.sources;
  }catch(x){const el=$('#mv-srcs');if(el)el.innerHTML='<div class="mv-note">'+e(x.message)+'</div>'}
}
async function send(magnet,quality){
  if(!MV.cfg.leecher){alert('Set LEECH_URL and LEECH_KEY for the vault first.');return}
  try{await jpost('/api/movies/download',{...MV.ctx,magnet,quality});$('#mv-modal').classList.remove('on');await refresh();if(MV.view==='detail')detail(MV.ctx.type,MV.ctx.id)}catch(x){alert(x.message)}
}

/* ---- player ---- */
function play(key){
  const it=MV.lib.find(x=>x.key===key);if(!it||!it.fid)return;
  const v=$('#mv-video');v.innerHTML='';
  (it.subs||[]).forEach((s,i)=>{const t=document.createElement('track');t.kind='subtitles';t.label=s.name.replace(/\.srt$/i,'').slice(0,40);t.src='/api/movies/subs/'+s.fid;if(i===0)t.default=true;v.appendChild(t)});
  v.src='/api/movies/stream/'+it.fid;
  $('#mv-ptitle').textContent=it.title+(it.type==='series'?` · S${it.season}E${it.episode}`:'');
  $('#mv-player').classList.add('on');
  const p=prog()[it.fid];v.onloadedmetadata=()=>{if(p&&p.t>5&&p.t<v.duration-30)v.currentTime=p.t};
  let last=0;v.ontimeupdate=()=>{if(Date.now()-last>4000&&v.duration){last=Date.now();setProg(it.fid,v.currentTime,v.duration)}};
  v.play().catch(()=>{});
}
function stop(){const v=$('#mv-video');if(v.duration)setProg((MV.lib.find(x=>('/api/movies/stream/'+x.fid)===v.getAttribute('src'))||{}).fid,v.currentTime,v.duration);v.pause();v.removeAttribute('src');v.load();$('#mv-player').classList.remove('on')}

/* ---- downloads strip + polling ---- */
async function refresh(){
  try{const d=await jget('/api/movies/library');MV.lib=d.items}catch(_){return}
  const act=MV.lib.filter(ACTIVE);
  $('#mv-dl').innerHTML=act.map(it=>`<div class="mv-dli"><b style="min-width:0;flex:0 1 220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e(it.title)}${it.type==='series'?` S${it.season}E${it.episode}`:''}</b><div class="bar"><i style="width:${it.pct||0}%"></i></div><span class="mv-s">${e(it.status)} ${it.pct||0}% ${e(it.speed||'')} ${e(it.eta||'')}</span><button class="mv-btn s sm" data-cancel="${e(it.key)}">Cancel</button></div>`).join('')+MV.lib.filter(x=>x.status==='error'||x.status==='lost').map(it=>`<div class="mv-dli"><b>${e(it.title)}</b><span class="mv-s" style="color:var(--red);flex:1">${e(it.error||it.status)}</span><button class="mv-btn s sm" data-rm="${e(it.key)}">Dismiss</button></div>`).join('');
  if(MV.view==='lib')library();
}
function tick(){if($('#sec-movies').classList.contains('active')&&(MV.lib.some(ACTIVE)||MV.t++%5===0))refresh().then(()=>{if(MV.view==='detail'&&MV.cur&&MV.lib.some(x=>x.imdb===MV.cur.id&&['done','error'].includes(x.status))&&!MV._seen){}})}

/* ---- events ---- */
document.addEventListener('click',async ev=>{
  const t=ev.target.closest('[data-v],.mv-card,[data-act],[data-src],[data-dl],[data-play],[data-cancel],[data-rm],.mv-chip,#mv-more,#mv-magb,#mv-pclose');if(!t)return;
  if(t.dataset.v){$('#mv-q').value='';({home,movie:()=>browse('movie'),series:()=>browse('series'),lib:library})[t.dataset.v]();MV.type=t.dataset.v;return}
  if(t.matches('.mv-chip')&&t.dataset.g!==undefined){MV.genre=t.dataset.g;browse(MV.view);return}
  if(t.id==='mv-more'){browse(MV.view,true);return}
  if(t.id==='mv-pclose'){stop();return}
  if(t.dataset.act==='back'){$('#mv-q').value?search($('#mv-q').value):(['movie','series'].includes(MV.type)?browse(MV.type):MV.type==='lib'?library():home());return}
  if(t.dataset.act==='close'){$('#mv-modal').classList.remove('on');return}
  if(t.dataset.play){play(t.dataset.play);return}
  if(t.dataset.src){sources(t.dataset.src,t.dataset.s!=null?+t.dataset.s:null,t.dataset.e!=null?+t.dataset.e:null);return}
  if(t.dataset.dl!==undefined){const s=MV.srcs[+t.dataset.dl];send(s.magnet,s.quality);return}
  if(t.id==='mv-magb'){const v=$('#mv-mag').value.trim();if(v)send(v,'');return}
  if(t.dataset.cancel){await fetch('/api/movies/cancel/'+t.dataset.cancel,{method:'POST'});refresh();return}
  if(t.dataset.rm){await fetch('/api/movies/library/'+t.dataset.rm,{method:'DELETE'});refresh();return}
  if(t.classList.contains('mv-card')&&t.closest('#sec-movies')){
    if(t.dataset.lib){const it=MV.lib.find(x=>x.key===t.dataset.lib);if(it&&it.status==='done')play(it.key);else if(it)detail(it.type,it.imdb);return}
    detail(t.dataset.t,t.dataset.id)}
});
document.addEventListener('change',ev=>{if(ev.target.id==='mv-season')eps(ev.target.value)});
document.addEventListener('keydown',ev=>{if(ev.key==='Escape'){if($('#mv-player').classList.contains('on'))stop();else $('#mv-modal').classList.remove('on')}});
let st;document.addEventListener('input',ev=>{if(ev.target.id!=='mv-q')return;clearTimeout(st);const q=ev.target.value.trim();st=setTimeout(()=>q.length>1?search(q):home(),350)});
function init(){
  if(MV.inited)return;MV.inited=true;
  jget('/api/movies/config').then(c=>{MV.cfg=c;if(!c.leecher)$('#mv-dl').insertAdjacentHTML('beforebegin','<div class="mv-note">Browsing works. To download, set <code>LEECH_URL</code> and <code>LEECH_KEY</code> in the vault environment.</div>')}).catch(()=>{});
  refresh().then(home);setInterval(tick,3000);
}
document.querySelectorAll('[data-tab="movies"]').forEach(b=>b.addEventListener('click',init));
})();
</script>
"""


# ----------------------------------------------------------------------------- install
def install(app, ctx):
    """Register the API and return the vault page with the Movies & Series UI injected."""
    C.update({k: ctx[k] for k in ("scan_state", "scan_lock", "unseal", "CHUNK", "kick_scan", "__file__")})
    app.register_blueprint(bp)
    page = ctx["PAGE"]
    marks = ('<button data-tab="leech" title="Vault Leech">⬇️</button>',
             '<button class="tab" data-tab="leech">Vault Leech</button>',
             '<section id="sec-matrix"', '</body>')
    if any(m not in page for m in marks):
        raise RuntimeError("vault page layout changed; injection points not found")
    page = page.replace(marks[0], marks[0] + '\n    <button data-tab="movies" title="Movies &amp; Series">🍿</button>', 1)
    page = page.replace(marks[1], marks[1] + '\n        <button class="tab" data-tab="movies">Movies &amp; Series</button>', 1)
    page = page.replace(marks[2], _HTML + "\n      " + marks[2], 1)
    head, _, tail = page.rpartition(marks[3])
    return head + _CSS + _JS + marks[3] + tail
