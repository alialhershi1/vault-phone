"""Phone interface for the encrypted Discord vault. Runs behind Render's HTTPS proxy."""
import datetime, ipaddress, json, mimetypes, os, secrets, socket, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, abort, jsonify, request, send_from_directory
import vault_server as V

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "10000"))
app = Flask(__name__)
_lock = threading.Lock()
LIB = {"t": 0, "items": None}
NAMES = {}
FAILS = []
UPLOADS = {}

def authed():
    tok = V.KEY["token"]
    return bool(tok) and secrets.compare_digest(request.args.get("t", "").encode(), tok.encode())

def verify(aes):
    metas = [f["meta"] for f in V.scan().values() if "meta" in f][:3]
    if not metas: return True
    for url in metas:
        try:
            r = requests.get(url, timeout=60); r.raise_for_status()
            c = r.content
            aes.decrypt(c[:12], c[12:], None)
            return True
        except Exception: pass
    return False

def end_session():
    V.KEY["aes"] = V.KEY["token"] = None
    V.clear_stream_state()
    with _lock: LIB.update(t=0, items=None)

def library(force=False):
    with _lock:
        if LIB["items"] is not None and not force and time.time()-LIB["t"] < 60: return LIB["items"]
    found = V.scan()
    def one(kv):
        fid, f = kv
        if "meta" not in f: return None
        try:
            r = requests.get(f["meta"], timeout=60); r.raise_for_status()
            m = json.loads(V.unseal(r.content))
        except Exception: return None
        return {"id":fid,"name":m.get("name","?"),"type":m.get("type") or "",
                "size":m.get("size",0),"t":m.get("t",0),"ok":len(f["chunks"])==f["n"]}
    with ThreadPoolExecutor(8) as ex: items = [x for x in ex.map(one, found.items()) if x]
    items.sort(key=lambda x:x["t"], reverse=True)
    with _lock:
        LIB.update(t=time.time(),items=items)
        NAMES.clear(); NAMES.update({x["id"]:x for x in items})
    return items

@app.get("/")
def index():
    r = send_from_directory(HERE, "phone_v2.html")
    r.headers["Cache-Control"] = "no-store"
    return r

@app.get("/health")
def health(): return {"ok": True}

@app.post("/api/unlock")
def unlock():
    now=time.time()
    FAILS[:] = [x for x in FAILS if now-x < 300]
    if len(FAILS)>=8: return "Too many wrong tries. Wait a few minutes.",429
    pw=(request.get_json(silent=True) or {}).get("p","")
    if not pw: return "Enter the vault password.",400
    aes=AESGCM(PBKDF2HMAC(hashes.SHA256(),32,b"vault-v1",300000).derive(pw.encode()))
    if not verify(aes):
        FAILS.append(now); time.sleep(1); return "Incorrect vault password.",401
    V.clear_stream_state()
    with _lock: LIB.update(t=0,items=None)
    V.KEY["aes"],V.KEY["token"]=aes,secrets.token_urlsafe(24)
    return jsonify(t=V.KEY["token"])

@app.post("/api/lock")
def lock():
    if authed(): end_session()
    return "",204

@app.get("/api/library")
def lib():
    if not authed(): abort(403)
    return jsonify(library(force=bool(request.args.get("refresh"))))

@app.get("/api/stream/<fid>")
def stream(fid):
    r=V.stream(fid)
    it=NAMES.get(fid)
    if it:
        if r.mimetype=="application/octet-stream":
            mt=mimetypes.guess_type(it["name"])[0]
            if mt: r.mimetype=mt
        if request.args.get("dl"): r.headers["Content-Disposition"]="attachment; filename*=UTF-8''"+quote(it["name"])
    return r

def seal(data):
    iv=os.urandom(12)
    return iv+V.KEY["aes"].encrypt(iv,data,None)

@app.post("/api/upload/start")
def upload_start():
    if not authed(): abort(403)
    d=request.get_json(silent=True) or {}
    name=os.path.basename(str(d.get("name") or "file").replace("\\","/"))[:200] or "file"
    size=max(0,int(d.get("size",0)))
    mime=str(d.get("type") or mimetypes.guess_type(name)[0] or "")
    n=max(1,-(-size//V.CHUNK))
    fid=secrets.token_hex(6)
    meta=json.dumps({"name":name,"type":mime,"size":size,"t":int(time.time()*1000)}).encode()
    V.dc("POST",f"/channels/{V.CH}/messages",data={"content":f"v1 {fid} m {n}"},files={"files[0]":(f"m{fid}.bin",seal(meta))})
    UPLOADS[fid]={"n":n}
    return jsonify(id=fid,n=n,chunk=V.CHUNK)

@app.post("/api/upload/chunk")
def upload_chunk():
    if not authed(): abort(403)
    fid=request.args.get("id","")
    try: i=int(request.args.get("i","-1"))
    except ValueError: abort(400)
    u=UPLOADS.get(fid)
    if not u or not 0<=i<u["n"]: abort(400)
    data=request.get_data()
    if len(data)>V.CHUNK: abort(413)
    V.dc("POST",f"/channels/{V.CH}/messages",data={"content":f"v1 {fid} c{i} {u['n']}"},files={"files[0]":(f"{fid}.{i}.bin",seal(data))})
    if i==u["n"]-1:
        UPLOADS.pop(fid,None)
        with _lock: LIB.update(t=0,items=None)
    return "",204
