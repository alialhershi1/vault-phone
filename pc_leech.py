"""Local PC leech for the existing Discord vault.
Downloads are written only to PC_RAM_DIR (a RAM disk), then encrypted and
uploaded in the exact v1 format used by vault_server.py / the phone app.
"""
import json, os, re, secrets, shutil, subprocess, sys, threading, time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
from flask import Flask, abort, jsonify, request
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import vault_server as V

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "pc_leech_config.json"
try:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
except Exception:
    cfg = {}
ACCESS_KEY = str(os.environ.get("PC_LEECH_KEY") or cfg.get("PC_LEECH_KEY") or "")
RAM_ROOT = Path(os.environ.get("PC_RAM_DIR") or cfg.get("PC_RAM_DIR") or "").expanduser()
PORT = int(os.environ.get("PC_LEECH_PORT", "8790"))
app = Flask(__name__)
AES = None
JOBS, ORDER = {}, []
LOCK = threading.RLock()
QUEUE = []
WAKE = threading.Condition(LOCK)

def seal(data):
    iv = os.urandom(12)
    return iv + AES.encrypt(iv, data, None)

def authorized():
    supplied = request.headers.get("X-Key", "")
    if not ACCESS_KEY or not secrets.compare_digest(supplied, ACCESS_KEY):
        abort(401)

def publish(content, filename, blob):
    r = V.dc("POST", f"/channels/{V.CH}/messages",
             data={"content": content},
             files={"files[0]": (filename, blob)})
    payload = r.json()
    if not isinstance(payload, dict) or not payload.get("attachments"):
        raise RuntimeError("Discord did not confirm the uploaded attachment.")
    return payload.get("id")

def send_file(path, job):
    path = Path(path)
    size = path.stat().st_size
    if size <= 0:
        raise RuntimeError("Downloaded file is empty.")
    fid = secrets.token_hex(6)
    n = max(1, (size + V.CHUNK - 1) // V.CHUNK)
    meta = {"name": path.name[:200], "folder": "", "type": "",
            "size": size, "t": int(time.time() * 1000)}
    created = []
    try:
        mid = publish(f"v1 {fid} m {n}", f"m{fid}.bin",
                      seal(json.dumps(meta, separators=(",", ":")).encode()))
        created.append(mid)
        with path.open("rb") as src:
            for i in range(n):
                if job.get("cancel"):
                    raise RuntimeError("Cancelled.")
                chunk = src.read(V.CHUNK)
                if not chunk:
                    raise RuntimeError("RAM download ended before all chunks were read.")
                mid = publish(f"v1 {fid} c{i} {n}", f"{fid}.{i}.bin", seal(chunk))
                created.append(mid)
                job.update(pct=round(100 * (i + 1) / n), status="uploading",
                           detail=f"Uploaded chunk {i + 1}/{n}")
        job.update(status="done", pct=100, file_id=fid, size=size)
    except Exception:
        for mid in created:
            if mid:
                try: V.dc("DELETE", f"/channels/{V.CH}/messages/{mid}")
                except Exception: pass
        raise

def run_job(job):
    folder = RAM_ROOT / ("vault-leech-" + job["id"])
    folder.mkdir(parents=True, exist_ok=False)
    try:
        if not shutil.which("aria2c"):
            raise RuntimeError("aria2c was not found. Install aria2 and add aria2c.exe to PATH.")
        job.update(status="downloading", pct=0, detail="Downloading into RAM disk")
        cmd = ["aria2c", "--dir=" + str(folder), "--seed-time=0",
               "--summary-interval=1", "--console-log-level=notice",
               "--show-console-readout=true", "--file-allocation=none",
               "--max-connection-per-server=8", "--split=8",
               "--bt-max-peers=80", "--enable-dht=true",
               "--enable-peer-exchange=true", "--auto-file-renaming=false",
               "--allow-overwrite=true", job["link"]]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=0)
        job["proc"] = proc
        tail, line = [], ""
        while True:
            ch = proc.stdout.read(1)
            if ch == "":
                if line.strip(): tail = (tail + [line.strip()])[-8:]
                break
            if ch not in ("\r", "\n"):
                line += ch
                continue
            entry, line = line.strip(), ""
            if not entry: continue
            tail = (tail + [entry])[-8:]
            m = re.search(r"\((\d+)%\)", entry)
            if m: job["pct"] = int(m.group(1))
            m = re.search(r"DL:(\S+?)(?:\s|\])", entry)
            if m: job["speed"] = m.group(1) + "/s"
            m = re.search(r"ETA:(\S+?)\]", entry)
            if m: job["eta"] = m.group(1)
        rc = proc.wait()
        job["proc"] = None
        if job.get("cancel"): raise RuntimeError("Cancelled.")
        if rc:
            raise RuntimeError("aria2 failed (code %s): %s" % (rc, " | ".join(tail)[-220:]))
        files = []
        for p in folder.rglob("*"):
            if p.is_file() and p.suffix not in (".aria2", ".torrent") and p.stat().st_size:
                files.append(p)
        if not files: raise RuntimeError("aria2 finished but produced no files.")
        total = sum(p.stat().st_size for p in files)
        sent = 0
        for p in files:
            job.update(status="uploading", detail="Encrypting and sending " + p.name)
            send_file(p, job)
            sent += p.stat().st_size
        job.update(status="done", pct=100, detail=f"Saved {len(files)} file(s) to your Discord vault.",
                   files=len(files), size=total)
    except Exception as exc:
        job.update(status="cancelled" if job.get("cancel") else "error", error=str(exc)[:300])
    finally:
        job["proc"] = None
        shutil.rmtree(folder, ignore_errors=True)

def worker():
    while True:
        with WAKE:
            while not QUEUE: WAKE.wait()
            job = QUEUE.pop(0)
        run_job(job)

@app.get("/")
def index():
    return """<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>
<title>PC Vault Leech</title><style>
body{margin:0;background:#0d1420;color:#eaf0f8;font:15px system-ui;max-width:760px;padding:24px;margin:auto}
input,button{font:inherit;padding:12px;border-radius:9px;border:1px solid #40516a;background:#172334;color:#fff}
input{width:100%;box-sizing:border-box;margin:8px 0}button{background:#7295c4;color:#07111e;cursor:pointer}
.card{background:#172334;border:1px solid #30445c;border-radius:12px;padding:14px;margin:12px 0;overflow-wrap:anywhere}
small{color:#a9b9cc}progress{width:100%}</style>
<h2>PC Vault Leech</h2><p><small>Downloads run in RAM disk and upload into your existing encrypted Discord vault.</small></p>
<input id=key type=password placeholder='Local access key'><input id=link placeholder='Magnet or direct HTTP(S) link'>
<button id=add>Add download</button><div id=msg></div><div id=jobs></div>
<script>
const $=id=>document.getElementById(id);let key=sessionStorage.getItem('pc-leech-key')||'';
$('key').value=key;
async function api(url,opt={}){key=$('key').value;sessionStorage.setItem('pc-leech-key',key);let r=await fetch(url,{...opt,headers:{'Content-Type':'application/json','X-Key':key,...opt.headers}});let d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||d.message||'Request failed '+r.status);return d}
$('add').onclick=async()=>{try{const d=await api('/api/add',{method:'POST',body:JSON.stringify({link:$('link').value.trim()})});$('msg').textContent='Queued '+d.id;$('link').value='';load()}catch(e){$('msg').textContent=e.message}};
async function load(){try{let jobs=await api('/api/jobs');$('jobs').replaceChildren(...jobs.map(j=>{let d=document.createElement('div');d.className='card';let title=document.createElement('b');title.textContent=j.name||j.id;let s=document.createElement('p');s.textContent=j.status+' · '+(j.pct||0)+'% '+(j.speed||'')+' '+(j.eta||'')+' '+(j.detail||j.error||'');let p=document.createElement('progress');p.max=100;p.value=j.pct||0;d.append(title,s,p);if(['queued','downloading','uploading'].includes(j.status)){let b=document.createElement('button');b.textContent='Cancel';b.onclick=()=>api('/api/cancel/'+j.id,{method:'POST'});d.append(b)}return d}))}catch(e){$('msg').textContent=e.message}}
load();setInterval(load,2000);
</script>"""

@app.post("/api/add")
def add():
    authorized()
    link = str((request.get_json(silent=True) or {}).get("link") or "").strip()
    if not (link.startswith("magnet:?") or re.match(r"https?://", link)):
        return jsonify(error="Paste a magnet or HTTP(S) download link."), 400
    if not RAM_ROOT.exists():
        return jsonify(error="PC_RAM_DIR must point to an existing RAM disk folder. No disk fallback is allowed."), 503
    jid = secrets.token_hex(4)
    job = {"id": jid, "link": link, "name": unquote(urlparse(link).path.rsplit("/",1)[-1]) or "Magnet download",
           "status": "queued", "pct": 0, "cancel": False}
    with WAKE:
        JOBS[jid] = job
        ORDER.insert(0, jid)
        QUEUE.append(job)
        WAKE.notify()
    return jsonify({"id": jid, "name": job["name"], "status": "queued"})

@app.get("/api/jobs")
def jobs():
    authorized()
    with LOCK: return jsonify([{k:v for k,v in j.items() if k not in ("link","proc","cancel")} for j in (JOBS[x] for x in ORDER if x in JOBS)])

@app.post("/api/cancel/<jid>")
def cancel(jid):
    authorized()
    job = JOBS.get(jid)
    if not job: abort(404)
    job["cancel"] = True
    proc = job.get("proc")
    if proc:
        try: proc.terminate()
        except Exception: pass
    return "", 204

def main():
    global AES
    if not ACCESS_KEY or len(ACCESS_KEY) < 12:
        sys.exit("Set PC_LEECH_KEY (at least 12 characters) in pc_leech_config.json.")
    if not RAM_ROOT.exists():
        sys.exit("Set PC_RAM_DIR to an existing RAM disk folder. The app refuses to use normal disk storage.")
    pw = str(os.environ.get("VAULT_PASSWORD") or cfg.get("VAULT_PASSWORD") or "")
    if not pw:
        sys.exit("Add VAULT_PASSWORD to the private pc_leech_config.json.")
    AES = AESGCM(PBKDF2HMAC(SHA256(), 32, b"vault-v1", 300000).derive(pw.encode()))
    # Confirm the password against an existing encrypted metadata record before uploading.
    found = V.scan()
    checked = False
    for item in found.values():
        if not item.get("meta"): continue
        try:
            import requests
            r = requests.get(item["meta"], timeout=25); r.raise_for_status()
            blob = r.content
            AES.decrypt(blob[:12], blob[12:], None)
            checked = True
            break
        except Exception:
            continue
    if not checked and found:
        sys.exit("Could not verify VAULT_PASSWORD against existing vault metadata. Nothing uploaded.")
    if not found:
        print("Warning: vault has no existing files; password cannot be independently verified.")
    threading.Thread(target=worker, daemon=True).start()
    print(f"PC Vault Leech listening at http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, threaded=True)

if __name__ == "__main__":
    main()
