"""Durable Reel job queue. Postgres when DATABASE_URL is set, else a local
SQLite file (NOT durable on Render's free plan: the disk is wiped on restart).
Contains no secrets: only URLs, status and progress."""
import os, sqlite3, threading, time

DB_URL = os.environ.get("DATABASE_URL", "").strip()
PG = DB_URL.startswith(("postgres://", "postgresql://"))
SQLITE_PATH = os.environ.get("LEECH_QUEUE_SQLITE", "/tmp/reel_queue.db")
ERROR = ""          # last DB problem, shown in the UI
DURABLE = False
_psycopg = None
_claim_lock = threading.Lock()
SKIP = ""

def _connect():
    if PG:
        return _psycopg.connect(DB_URL, autocommit=True, connect_timeout=10)
    c = sqlite3.connect(SQLITE_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    return c

def _q(conn, sql, args=(), fetch=None):
    cur = conn.cursor()
    cur.execute(sql.replace("?", "%s") if PG else sql, args)
    if fetch:
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return rows if fetch == "all" else (rows[0] if rows else None)
    return cur.rowcount

def _run(sql, args=(), fetch=None):
    conn = _connect()
    try:
        return _q(conn, sql, args, fetch)
    finally:
        conn.close()

def init():
    """Create tables and requeue anything a crash left mid-flight."""
    global PG, DURABLE, ERROR, SKIP, _psycopg
    if PG:
        try:
            import psycopg as _p
            _psycopg = _p
        except Exception as e:
            ERROR = "psycopg missing (%s); using non-durable fallback." % e
            PG = False
    pk = "BIGSERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
    ddl = [
        "CREATE TABLE IF NOT EXISTS leech_jobs(id %s, url TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'queued',"
        " attempts INTEGER NOT NULL DEFAULT 0, next_try DOUBLE PRECISION NOT NULL DEFAULT 0, percent INTEGER NOT NULL DEFAULT 0,"
        " message TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT 'Instagram Reel', file_id TEXT,"
        " created DOUBLE PRECISION NOT NULL, updated DOUBLE PRECISION NOT NULL)" % pk,
        "CREATE INDEX IF NOT EXISTS leech_jobs_status ON leech_jobs(status, id)",
        "CREATE TABLE IF NOT EXISTS leech_kv(k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    ]
    last = None
    for _ in range(3):
        try:
            conn = _connect()
            try:
                for s in ddl:
                    _q(conn, s)
                _q(conn, "UPDATE leech_jobs SET status='queued', message='Recovered after restart', updated=? "
                         "WHERE status IN ('downloading','storing')", (time.time(),))
            finally:
                conn.close()
            DURABLE = PG
            SKIP = "FOR UPDATE SKIP LOCKED" if PG else ""
            if not PG and not ERROR:
                ERROR = "DATABASE_URL is not set: queue is NOT persistent across restarts."
            return
        except Exception as e:
            last = e
            time.sleep(2)
    if PG:  # DB unreachable: degrade loudly instead of crashing the app
        ERROR = "Postgres unreachable (%s); using non-durable fallback." % str(last)[:120]
        PG = False
        init()

def add_many(urls):
    """Insert URLs. Returns (added, duplicates, requeued). Failed duplicates are re-queued."""
    added = dup = requeued = 0
    now = time.time()
    conn = _connect()
    try:
        for u in urls:
            n = _q(conn, "INSERT INTO leech_jobs(url,status,created,updated) VALUES(?,'queued',?,?) "
                         "ON CONFLICT(url) DO NOTHING", (u, now, now))
            if n == 1:
                added += 1
            else:
                r = _q(conn, "UPDATE leech_jobs SET status='queued', attempts=0, next_try=0, percent=0, "
                             "message='Re-queued', updated=? WHERE url=? AND status='failed'", (now, u))
                if r == 1:
                    requeued += 1
                else:
                    dup += 1
    finally:
        conn.close()
    return added, dup, requeued

def claim():
    with _claim_lock:
        now = time.time()
        return _run(
            "UPDATE leech_jobs SET status='downloading', attempts=attempts+1, percent=0, message='Starting…', updated=? "
            "WHERE id=(SELECT id FROM leech_jobs WHERE status='queued' AND next_try<=? ORDER BY id LIMIT 1 " + SKIP + ") "
            "AND status='queued' RETURNING id,url,attempts,file_id,title", (now, now), "one")

_COLS = {"status", "attempts", "next_try", "percent", "message", "title", "file_id"}

def update(job_id, **vals):
    vals = {k: v for k, v in vals.items() if k in _COLS}
    if not vals:
        return
    sets = ", ".join(k + "=?" for k in vals) + ", updated=?"
    try:
        _run("UPDATE leech_jobs SET " + sets + " WHERE id=?", (*vals.values(), time.time(), job_id))
    except Exception:
        pass  # progress updates are best-effort

def summary():
    rows = _run("SELECT status, COUNT(*) AS c FROM leech_jobs GROUP BY status", (), "all") or []
    s = {k: 0 for k in ("queued", "downloading", "storing", "completed", "failed")}
    for r in rows:
        s[r["status"]] = int(r["c"])
    s["active"] = s["queued"] + s["downloading"] + s["storing"]
    s["remaining"] = s["active"]
    s["total"] = sum(s[k] for k in ("queued", "downloading", "storing", "completed", "failed"))
    s["durable"] = DURABLE
    s["db_note"] = ERROR
    return s

def listing(limit=50, offset=0, status=None):
    where, args = "", []
    if status in ("queued", "downloading", "storing", "completed", "failed"):
        where, args = "WHERE status=?", [status]
    return _run(
        "SELECT id,url,status,percent,message,title,file_id,attempts,created,updated FROM leech_jobs " + where +
        " ORDER BY CASE status WHEN 'downloading' THEN 0 WHEN 'storing' THEN 0 WHEN 'failed' THEN 1 "
        "WHEN 'queued' THEN 2 ELSE 3 END, CASE WHEN status='queued' THEN id END ASC, updated DESC LIMIT ? OFFSET ?",
        (*args, int(limit), int(offset)), "all") or []

def retry_failed():
    return _run("UPDATE leech_jobs SET status='queued', attempts=0, next_try=0, percent=0, message='Re-queued', "
                "updated=? WHERE status='failed'", (time.time(),))

def kv_get(k):
    r = _run("SELECT v FROM leech_kv WHERE k=?", (k,), "one")
    return r["v"] if r else None

def kv_set(k, v):
    _run("INSERT INTO leech_kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
