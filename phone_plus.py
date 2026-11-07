"""Render entry point for the upgraded Vault phone app."""
import json, os, requests
from flask import abort, jsonify, request
import phone_server as P
V, app = P.V, P.app

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
        name=os.path.basename(str(d.get("name") or "").replace("\\","/"))[:200]
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

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","10000")),threaded=True)
