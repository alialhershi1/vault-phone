"""Vault LEECH server: downloads torrents / magnet links / direct links ON THE SERVER and sends them straight into your
encrypted Discord vault. Nothing goes through your PC. Run it on an always-on machine (a VPS or home server), not on your PC.

Needs (on that server):  aria2   +   pip install flask requests cryptography
Put it in the same folder as vault_server.py (it only reads your token and channel from there, nothing is changed).
Set two secrets before starting:
    VAULT_PASSWORD = your vault password (used to encrypt, same one you unlock the vault with)
    LEECH_KEY      = a long random access key for this page (you choose it)
Linux:    export VAULT_PASSWORD='...' LEECH_KEY='...' ; python3 vault_leech.py
Then open  http://SERVER-IP:8790  and enter the access key once."""
import json, mimetypes, os, queue, re, secrets, shutil, subprocess, sys, threading, time, tempfile, random
from urllib.parse import parse_qs, unquote, urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, Response, abort, jsonify, request

import vault_server as V   # token, channel and the 9 MB chunk size only
import reel_queue as Q   # durable Instagram/Reels job queue

HERE = os.path.dirname(os.path.abspath(__file__))
DL = os.path.join(HERE, "leech_tmp")      # temporary download folder, emptied after each job
PORT = int(os.environ.get("LEECH_PORT") or os.environ.get("PORT") or 8790)   # hosts like Render set PORT themselves
app = Flask(__name__)
AES = None
JOBS, ORDER, JOB_Q = {}, [], queue.Queue()
LOCK = threading.Lock()

# Social-video downloads use their own queue, worker, and temporary folders.
# They never occupy the magnet worker or alter its queue.
SOCIAL_JOBS, SOCIAL_ORDER, SOCIAL_Q = {}, [], queue.Queue()
SOCIAL_LOCK = threading.Lock()
SOCIAL_HOSTS = {"youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
                "instagram.com", "www.instagram.com"}


class Cancelled(Exception):
    pass


def seal(b):
    iv = os.urandom(12)
    return iv + AES.encrypt(iv, b, None)


def send(content, fname, blob):
    for a in range(6):
        try:
            V.dc("POST", f"/channels/{V.CH}/messages", data={"content": content}, files={"files[0]": (fname, blob)})
            return
        except Exception:
            if a == 5:
                raise
            time.sleep(min(30, 3 * (a + 1)))


def put_file(path, name, job, base_done, total):
    size = os.path.getsize(path)
    n = max(1, -(-size // V.CHUNK))
    fid = secrets.token_hex(6)
    mime = mimetypes.guess_type(name)[0] or ""
    meta = json.dumps({"name": name, "type": mime, "size": size, "t": int(time.time() * 1000)}).encode()
    # Upload all encrypted chunks first. The metadata message is the final
    # commit marker, so the vault never indexes a partially uploaded file.
    with open(path, "rb") as f:
        for i in range(n):
            if job["cancel"]:
                raise Cancelled()
            data = f.read(V.CHUNK)
            if not data:
                raise RuntimeError("The downloaded file ended before all chunks were read.")
            send(f"v1 {fid} c{i} {n}", f"{fid}.{i}.bin", seal(data))
            job["pct"] = round(100 * (base_done + min(size, (i + 1) * V.CHUNK)) / max(1, total))
    send(f"v1 {fid} m {n}", f"m{fid}.bin", seal(meta))
    job.setdefault("fids", []).append({"fid": fid, "name": name, "size": size})   # lets the Vault register the file
    return size


def guess_name(link):
    if link.startswith("magnet:"):
        dn = parse_qs(urlparse(link).query).get("dn")
        return dn[0] if dn else "magnet link"
    return unquote(os.path.basename(urlparse(link).path)) or link[:60]


def run(job):
    d = os.path.join(DL, job["id"])
    os.makedirs(d, exist_ok=True)
    try:
        job["status"] = "downloading"
        cmd = ["aria2c", "--dir=" + d, "--seed-time=0", "--summary-interval=2",
               "--console-log-level=notice", "--show-console-readout=true",
               "--file-allocation=none", "--max-connection-per-server=8", "--split=8",
               "--bt-max-peers=100", "--enable-dht=true", "--enable-peer-exchange=true",
               "--bt-enable-lpd=true", "--bt-tracker-connect-timeout=15", "--bt-tracker-timeout=30",
               "--connect-timeout=15", "--timeout=60", "--follow-torrent=true",
               "--auto-file-renaming=false", "--allow-overwrite=true", "--bt-stop-timeout=900", job["link"]]
        # aria2 refreshes its progress display with carriage returns, not just newlines.
        # Read both delimiters so progress and tracker/metadata diagnostics reach the UI.
        job["proc"] = p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, bufsize=1)
        tail, line = [], ""
        while True:
            ch = p.stdout.read(1)
            if ch == "":
                if line.strip():
                    tail = (tail + [line.strip()])[-8:]
                break
            if ch not in ("\r", "\n"):
                line += ch
                continue
            if not line.strip():
                line = ""
                continue
            entry, line = line.strip(), ""
            tail = (tail + [entry])[-16:]
            m = re.search(r"\((\d+)%\)", entry)
            if m:
                job["pct"] = int(m.group(1))
            m = re.search(r"DL:(\S+?)(?:\s|\])", entry)
            if m:
                job["speed"] = m.group(1) + "/s"
            m = re.search(r"ETA:(\S+?)\]", entry)
            if m:
                job["eta"] = m.group(1)
            # Keep the latest aria2 diagnostic visible if the torrent cannot find peers.
            if any(word in entry.lower() for word in ("error", "failed", "no peers", "tracker")):
                job["error"] = entry[:180]
        rc = p.wait()
        job["proc"] = None
        if job["cancel"]:
            raise Cancelled()
        if rc != 0:
            raise RuntimeError("Download failed (aria2 code %d). %s" % (rc, " | ".join(tail)[:200]))
        files = []
        for root, _, names in os.walk(d):
            for nme in names:
                if nme.endswith((".aria2", ".torrent")):
                    continue
                fp = os.path.join(root, nme)
                if os.path.getsize(fp) > 0:
                    files.append(fp)
        if not files:
            raise RuntimeError("Nothing was downloaded.")
        files.sort()
        total = sum(os.path.getsize(f) for f in files)
        job.update(status="uploading", pct=0, speed="", eta="", name=os.path.basename(files[0]) if len(files) == 1 else f"{len(files)} files")
        done = 0
        for fp in files:
            done += put_file(fp, os.path.basename(fp), job, done, total)
            os.remove(fp)   # free the disk as soon as each file is in the vault
        job.update(status="done", pct=100, files=len(files), size=total)
    except Cancelled:
        job["status"] = "cancelled"
    except Exception as e:
        job["status"], job["error"] = "error", str(e)[:1100]
    finally:
        job["proc"] = None
        shutil.rmtree(d, ignore_errors=True)


def worker():
    while True:
        job = JOB_Q.get()
        if job["cancel"]:
            job["status"] = "cancelled"
        else:
            run(job)



def social_host_ok(link):
    try:
        u = urlparse(link)
        host = (u.hostname or "").lower()
        path = u.path.lower()
        if u.scheme != "https" or host not in SOCIAL_HOSTS:
            return False
        if host.endswith("youtube.com"):
            return path == "/watch" or path.startswith(("/shorts/", "/live/", "/embed/"))
        if host == "youtu.be":
            return len(path.strip("/")) > 0
        return path.startswith(("/reel/", "/reels/", "/p/", "/tv/"))
    except Exception:
        return False


def run_social(job):
    d = os.path.join(DL, "social_" + job["id"])
    os.makedirs(d, exist_ok=True)
    try:
        job["status"] = "downloading"
        # Public/accessible single videos only: no playlist expansion, cookies,
        # login automation, or access-control bypass.
        template = os.path.join(d, "%(title).150B.%(ext)s")
        cmd = ["yt-dlp", "--js-runtimes", "deno",
               "--extractor-retries", "3", "--retry-sleep", "extractor:2",
               "--socket-timeout", "20", "--verbose",
               "--no-playlist", "--max-downloads", "1",
               "--newline", "--progress", "--no-warnings",
               "--format", "best[ext=mp4]/best",
               "--output", template, job["link"]]
        job["proc"] = p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True,
                                           bufsize=1)
        tail = []
        for entry in p.stdout:
            if job["cancel"]:
                p.terminate()
                raise Cancelled()
            entry = entry.strip()
            if not entry:
                continue
            tail = (tail + [entry])[-8:]
            m = re.search(r"(\d+(?:\.\d+)?)%", entry)
            if m:
                job["pct"] = min(99, int(float(m.group(1))))
            m = re.search(r" at (\S+)", entry)
            if m:
                job["speed"] = m.group(1)
            m = re.search(r"ETA (\S+)", entry)
            if m:
                job["eta"] = m.group(1)
        rc = p.wait()
        job["proc"] = None
        if job["cancel"]:
            raise Cancelled()
        if rc != 0:
            raise RuntimeError("Social video download failed. " + " | ".join(tail)[-1000:])
        files = []
        for root, _, names in os.walk(d):
            for nme in names:
                fp = os.path.join(root, nme)
                if os.path.isfile(fp) and os.path.getsize(fp) > 0 and not nme.endswith((".part", ".ytdl")):
                    files.append(fp)
        if not files:
            raise RuntimeError("No video file was produced. The post may be private, unavailable, or require sign-in.")
        files.sort(key=lambda x: os.path.getsize(x), reverse=True)
        fp = files[0]
        total = os.path.getsize(fp)
        job.update(status="uploading", pct=0, speed="", eta="", name=os.path.basename(fp))
        put_file(fp, os.path.basename(fp), job, 0, total)
        job.update(status="done", pct=100, files=1, size=total)
    except Cancelled:
        job["status"] = "cancelled"
    except Exception as e:
        job["status"], job["error"] = "error", str(e)[:1200]
    finally:
        job["proc"] = None
        shutil.rmtree(d, ignore_errors=True)


def social_worker():
    while True:
        job = SOCIAL_Q.get()
        if job["cancel"]:
            job["status"] = "cancelled"
        else:
            run_social(job)


def need():
    k = request.headers.get("X-Key", "")
    if not secrets.compare_digest(k.encode(), os.environ.get("LEECH_KEY", "").encode() or b"\0"):
        time.sleep(1)
        abort(401)


def pub(j):
    return {k: j.get(k) for k in ("id", "name", "status", "pct", "speed", "eta", "error", "files", "size", "fids")}


@app.post("/api/add")
def add():
    need()
    link = str((request.get_json(silent=True) or {}).get("link", "")).strip()
    if not (link.startswith("magnet:?") or re.match(r"https?://", link)):
        return "Paste a magnet link or an http(s) link.", 400
    job = {"id": secrets.token_hex(4), "link": link, "name": guess_name(link), "status": "queued", "pct": 0, "cancel": False}
    with LOCK:
        JOBS[job["id"]] = job
        ORDER.insert(0, job["id"])
        for old in ORDER[40:]:
            JOBS.pop(old, None)
        del ORDER[40:]
    JOB_Q.put(job)
    return jsonify(pub(job))



@app.post("/api/social/add")
def add_social():
    need()
    link = str((request.get_json(silent=True) or {}).get("link", "")).strip()
    if not social_host_ok(link):
        return "Use an HTTPS YouTube or Instagram video URL.", 400
    job = {"id": secrets.token_hex(4), "link": link, "name": "Social video",
           "status": "queued", "pct": 0, "cancel": False}
    with SOCIAL_LOCK:
        SOCIAL_JOBS[job["id"]] = job
        SOCIAL_ORDER.insert(0, job["id"])
        for old in SOCIAL_ORDER[40:]:
            SOCIAL_JOBS.pop(old, None)
        del SOCIAL_ORDER[40:]
    SOCIAL_Q.put(job)
    return jsonify(pub(job))


@app.get("/api/social/jobs")
def social_jobs():
    need()
    return jsonify([pub(SOCIAL_JOBS[i]) for i in SOCIAL_ORDER if i in SOCIAL_JOBS])


@app.post("/api/social/cancel/<jid>")
def cancel_social(jid):
    need()
    j = SOCIAL_JOBS.get(jid) or abort(404)
    j["cancel"] = True
    p = j.get("proc")
    if p:
        try:
            p.terminate()
        except Exception:
            pass
    return "", 204


@app.get("/api/jobs")
def jobs():
    need()
    return jsonify([pub(JOBS[i]) for i in ORDER if i in JOBS])


@app.post("/api/cancel/<jid>")
def cancel(jid):
    need()
    j = JOBS.get(jid) or abort(404)
    j["cancel"] = True
    p = j.get("proc")
    if p:
        try:
            p.terminate()
        except Exception:
            pass
    return "", 204


PAGE = """<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Vault leech</title>
<style>:root{--bg:#0c121b;--p:#141d2a;--l:#243246;--t:#e7edf5;--m:#8796ab;--a:#6fd3c4;--r:#ff7a7a}*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--t);font:15px/1.5 system-ui,sans-serif}main{max-width:720px;margin:0 auto;padding:20px 16px 60px}
h1{font:600 26px ui-serif,Georgia,serif;margin:6px 0 4px}p{color:var(--m);margin:0 0 18px}
.b{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:14px;margin-bottom:14px}
input{width:100%;background:var(--bg);color:var(--t);border:1px solid var(--l);border-radius:8px;padding:11px;font:inherit}
button{background:var(--a);color:#06201c;border:0;border-radius:8px;padding:10px 16px;font:600 14px inherit;cursor:pointer;margin-top:10px}
button.g{background:none;color:var(--r);border:1px solid var(--l);margin:0;padding:6px 12px}
.n{overflow-wrap:anywhere;font-weight:600}.s{color:var(--m);font-size:13px}.e{color:var(--r)}
.bar{height:6px;background:var(--l);border-radius:3px;overflow:hidden;margin:8px 0 4px}.bar i{display:block;height:100%;background:var(--a);width:0}
.j{display:flex;gap:10px;justify-content:space-between;align-items:flex-start}</style>
<main><h1>Vault leech</h1><p>Paste a magnet or download link. The server downloads it and puts it straight into your vault.</p>
<div class=b><input id=l placeholder="magnet:?xt=... or https://..." autocomplete=off><button id=add>Add</button><div id=m class=s style="margin-top:8px"></div></div>
<div id=list></div>
<h2 style="font-size:19px;margin:26px 0 8px">YouTube / Instagram</h2>
<p>Paste a public video link you own or have permission to save. This runs separately from magnet downloads.</p>
<div class=b><input id=socialLink placeholder="https://youtu.be/... or https://www.instagram.com/reel/..." autocomplete=off><button id=socialAdd>Download video</button><div id=socialMsg class=s style="margin-top:8px"></div></div>
<div id=socialList></div></main>
<script>
const $=s=>document.querySelector(s);let K=localStorage.getItem('lk')||'';
async function api(p,o={}){if(!K){K=prompt('Access key')||'';localStorage.setItem('lk',K)}
const r=await fetch(p,{...o,headers:{'Content-Type':'application/json','X-Key':K}});
if(r.status===401){localStorage.removeItem('lk');K='';throw new Error('Wrong access key')}
if(!r.ok)throw new Error(await r.text());return r}
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
const lab={queued:'Waiting',downloading:'Downloading',uploading:'Sending to vault',done:'Done, it is in your vault',error:'Failed',cancelled:'Cancelled'};
async function load(){try{const js=await(await api('/api/jobs')).json(),box=$('#list');box.replaceChildren();
for(const j of js){const b=el('div','b'),row=el('div','j'),left=el('div'),n=el('div','n',j.name);
const act=['queued','downloading','uploading'].includes(j.status);
const s=el('div','s'+(j.status==='error'?' e':''),(lab[j.status]||j.status)+(act&&j.status!=='queued'?' · '+j.pct+'%':'')+(j.speed?' · '+j.speed:'')+(j.eta?' · '+j.eta+' left':'')+(j.error?' · '+j.error:''));
const bar=el('div','bar'),i=el('i');i.style.width=(j.status==='done'?100:j.pct||0)+'%';bar.append(i);left.append(n,bar,s);row.append(left);
if(act){const c=el('button','g','Cancel');c.onclick=()=>api('/api/cancel/'+j.id,{method:'POST'}).then(load);row.append(c)}
b.append(row);box.append(b)}}catch(e){$('#m').textContent=e.message}}

async function loadSocial(){try{const js=await(await api('/api/social/jobs')).json(),box=$('#socialList');box.replaceChildren();
for(const j of js){const b=el('div','b'),row=el('div','j'),left=el('div'),n=el('div','n',j.name);
const act=['queued','downloading','uploading'].includes(j.status);
const s=el('div','s'+(j.status==='error'?' e':''),(lab[j.status]||j.status)+(act&&j.status!=='queued'?' · '+j.pct+'%':'')+(j.speed?' · '+j.speed:'')+(j.eta?' · '+j.eta+' left':'')+(j.error?' · '+j.error:''));
const bar=el('div','bar'),i=el('i');i.style.width=(j.status==='done'?100:j.pct||0)+'%';bar.append(i);left.append(n,bar,s);row.append(left);
if(act){const c=el('button','g','Cancel');c.onclick=()=>api('/api/social/cancel/'+j.id,{method:'POST'}).then(loadSocial);row.append(c)}
b.append(row);box.append(b)}}catch(e){$('#socialMsg').textContent=e.message}}
$('#socialAdd').onclick=async()=>{const v=$('#socialLink').value.trim();if(!v)return;try{await api('/api/social/add',{method:'POST',body:JSON.stringify({link:v})});$('#socialLink').value='';$('#socialMsg').textContent='';loadSocial()}catch(e){$('#socialMsg').textContent=e.message}};
$('#socialLink').onkeydown=e=>{if(e.key==='Enter')$('#socialAdd').click()};
$('#add').onclick=async()=>{const v=$('#l').value.trim();if(!v)return;try{await api('/api/add',{method:'POST',body:JSON.stringify({link:v})});$('#l').value='';$('#m').textContent='';load()}catch(e){$('#m').textContent=e.message}};
$('#l').onkeydown=e=>{if(e.key==='Enter')$('#add').click()};
load();loadSocial();setInterval(()=>{load();loadSocial()},2500);
</script></html>"""


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html", headers={"Cache-Control": "no-store"})


def validate_pc_vault_contract(password):
    """Fail early unless this uploader matches the PC Vault v1 storage contract."""
    expected_chunk = 9 * 1024 * 1024
    if getattr(V, "CHUNK", None) != expected_chunk:
        raise RuntimeError(
            "Vault format mismatch: the PC Vault requires 9 MiB chunks. "
            "Check vault_server.py; no files have been uploaded."
        )
    if not getattr(V, "CH", ""):
        raise RuntimeError(
            "Discord vault channel is not configured. Set DISCORD_TOKEN and "
            "DISCORD_CHANNEL in Render (or configure vault_server.py)."
        )
    auth = V.S.headers.get("Authorization", "")
    if not auth.startswith("Bot "):
        raise RuntimeError(
            "Discord bot token is not configured. Set DISCORD_TOKEN in Render."
        )

    # Verify the exact PC Vault key derivation and AES-GCM envelope locally.
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"vault-v1",
        iterations=300000,
    ).derive(password.encode())
    probe = AESGCM(key)
    nonce = os.urandom(12)
    sample = b"PC Vault v1 compatibility check"
    encrypted = nonce + probe.encrypt(nonce, sample, None)
    if probe.decrypt(encrypted[:12], encrypted[12:], None) != sample:
        raise RuntimeError("PC Vault encryption compatibility check failed.")

    # Confirm that the configured bot can actually access the selected channel.
    channel = V.dc("GET", f"/channels/{V.CH}").json()
    if str(channel.get("id", "")) != str(V.CH):
        raise RuntimeError(
            "Discord did not confirm the configured vault channel. "
            "Check DISCORD_TOKEN and DISCORD_CHANNEL."
        )
    return AESGCM(key)


def main():
    global AES
    pw, key = os.environ.get("VAULT_PASSWORD"), os.environ.get("LEECH_KEY")
    if not pw or not key or len(key) < 12:
        sys.exit("Set VAULT_PASSWORD and LEECH_KEY (at least 12 characters) first. See the top of this file.")
    try:
        AES = validate_pc_vault_contract(pw)
    except Exception as e:
        sys.exit("PC Vault compatibility check failed: " + str(e))
    if not shutil.which("aria2c"):
        sys.exit("aria2 is not installed. On Debian/Ubuntu/Mint:  sudo apt install aria2")
    os.makedirs(DL, exist_ok=True)
    if not shutil.which("yt-dlp"):
        sys.exit("yt-dlp is not installed. Rebuild the Docker image.")
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=social_worker, daemon=True).start()
    print(
        f"\nPC Vault v1 compatibility confirmed (9 MiB chunks, AES-GCM/PBKDF2, "
        f"Discord channel {V.CH}).\n"
        f"Vault leech running on port {PORT}. Open http://SERVER-IP:{PORT} "
        "and enter your access key.\n"
    )
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# Phone Vault integration: durable Instagram Reel queue + API.
# The standalone magnet/social Leecher above remains available unchanged.
# ---------------------------------------------------------------------------
MAX_BYTES = 500 * 1024 * 1024
_WAKE = threading.Event()
_REEL_RUNTIME = {"app": None, "store": None, "load_key": None, "started": False}
_REEL_URL_RE = re.compile(r"^https?://(?:www\\.)?instagram\\.com/(?:reel|reels|p)/[A-Za-z0-9_-]+/?(?:\\?.*)?$", re.I)


def _valid_reel_url(raw):
    value = str(raw or "").strip()
    return value if len(value) <= 2048 and _REEL_URL_RE.match(value) else None


def _reel_worker():
    import yt_dlp
    while True:
        try:
            if not V.KEY.get("aes"):
                loader = _REEL_RUNTIME.get("load_key")
                if loader:
                    loader()
            if not V.KEY.get("aes"):
                _WAKE.wait(8)
                _WAKE.clear()
                continue
            job = Q.claim()
            if not job:
                _WAKE.wait(8)
                _WAKE.clear()
                continue
            jid = job["id"]
            temp_dir = tempfile.mkdtemp(prefix="vault-reel-")
            try:
                last_update = [0.0]
                def progress(data):
                    now = time.time()
                    if data.get("status") == "downloading" and now - last_update[0] > 2:
                        last_update[0] = now
                        total = data.get("total_bytes") or data.get("total_bytes_estimate") or 0
                        done = data.get("downloaded_bytes") or 0
                        pct = min(79, int(done * 79 / total)) if total else 1
                        Q.update(jid, percent=pct,
                                 message="Downloading Reel · " + str(data.get("_percent_str", "working")).strip())
                opts = {
                    "format": "best[ext=mp4]/best",
                    "outtmpl": os.path.join(temp_dir, "%(id)s.%(ext)s"),
                    "noplaylist": True, "quiet": True, "no_warnings": True,
                    "restrictfilenames": True, "socket_timeout": 30,
                    "retries": 2, "fragment_retries": 2, "extractor_retries": 1,
                    "max_filesize": MAX_BYTES, "progress_hooks": [progress],
                }
                cookie_text = os.environ.get("IG_COOKIES", "").strip()
                if cookie_text:
                    cookie_path = os.path.join(temp_dir, "cookies.txt")
                    with open(cookie_path, "w", encoding="utf-8") as fh:
                        fh.write(cookie_text + "\n")
                    opts["cookiefile"] = cookie_path
                with yt_dlp.YoutubeDL(opts) as dl:
                    info = dl.extract_info(job["url"], download=True)
                    if not info:
                        raise RuntimeError("Instagram did not provide a downloadable video.")
                    path = dl.prepare_filename(info)
                if not os.path.isfile(path):
                    candidates = [os.path.join(temp_dir, n) for n in os.listdir(temp_dir)
                                  if n != "cookies.txt" and os.path.isfile(os.path.join(temp_dir, n))]
                    if not candidates:
                        raise RuntimeError("Downloaded video file was not found.")
                    path = candidates[0]
                size = os.path.getsize(path)
                if not 0 < size <= MAX_BYTES:
                    raise RuntimeError("Video is empty or exceeds the 500 MB limit.")
                ext = os.path.splitext(path)[1].lstrip(".") or "mp4"
                stem = re.sub(r"[^A-Za-z0-9._ -]+", "_", str(info.get("title") or info.get("id") or "Instagram Reel"))
                filename = (stem[:150].strip(" ._") or "Instagram Reel") + "." + ext
                Q.update(jid, status="storing", percent=80, title=filename,
                         message="Encrypting and sending to Discord…")
                fid = _REEL_RUNTIME["store"](path, filename, jid, job["url"])
                Q.update(jid, status="completed", percent=100, file_id=fid,
                         title=filename, message="Saved in your Discord Vault · Reels")
            except Exception as exc:
                message = str(exc).strip() or "Download failed."
                low = message.lower()
                permanent = any(x in low for x in ("private", "login required", "unavailable", "not found", "404", "age-restricted"))
                attempts = int(job.get("attempts") or 1)
                if not permanent and attempts < 5:
                    delay = min(1800, 30 * (2 ** max(0, attempts - 1))) + random.uniform(0, 8)
                    Q.update(jid, status="queued", next_try=time.time() + delay, percent=0,
                             message=("Retry scheduled: " + message[:130]))
                else:
                    Q.update(jid, status="failed", message=message[:220])
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
            time.sleep(random.uniform(2, 4))
        except Exception as exc:
            print("Vault Reel worker error:", str(exc)[:300], flush=True)
            time.sleep(8)


def register(app, authed, store_callback, load_key_callback):
    """Attach Reel endpoints and start two durable queue workers exactly once."""
    _REEL_RUNTIME.update(app=app, store=store_callback, load_key=load_key_callback)

    @app.post("/api/reels/download")
    def reels_download():
        if not authed():
            abort(403)
        raw_urls = (request.get_json(silent=True) or {}).get("urls") or []
        if not isinstance(raw_urls, list):
            return "Send a list of Instagram Reel URLs.", 400
        if len(raw_urls) > 100:
            return "Send at most 100 links per request.", 413
        valid, seen, invalid, duplicates = [], set(), 0, 0
        for raw in raw_urls:
            url = _valid_reel_url(raw)
            if not url:
                invalid += 1
            elif url in seen:
                duplicates += 1
            else:
                seen.add(url)
                valid.append(url)
        added = requeued = db_duplicates = 0
        if valid:
            try:
                added, db_duplicates, requeued = Q.add_many(valid)
            except Exception as exc:
                return ("Queue storage failed: " + str(exc)[:180]), 503
            _WAKE.set()
        return jsonify(submitted=len(raw_urls), added=added, requeued=requeued,
                       duplicates=duplicates + db_duplicates, invalid=invalid,
                       summary=Q.summary())

    @app.get("/api/reels/jobs")
    def reels_jobs():
        if not authed():
            abort(403)
        try:
            limit = min(200, max(1, int(request.args.get("limit", 50))))
            offset = max(0, int(request.args.get("offset", 0)))
            return jsonify(jobs=Q.listing(limit, offset, request.args.get("status")),
                           summary=Q.summary())
        except Exception as exc:
            return ("Queue read failed: " + str(exc)[:180]), 503

    @app.post("/api/reels/retry_failed")
    def reels_retry_failed():
        if not authed():
            abort(403)
        count = Q.retry_failed()
        _WAKE.set()
        return jsonify(requeued=count, summary=Q.summary())

    if not _REEL_RUNTIME["started"]:
        Q.init()
        for _ in range(2):
            threading.Thread(target=_reel_worker, daemon=True).start()
        _REEL_RUNTIME["started"] = True
    return True
