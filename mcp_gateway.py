"""Authenticated Streamable HTTP MCP bridge for the encrypted Vault."""
import contextlib
import hmac
import json
import os
import re
import tempfile
import threading

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware.wsgi import WSGIMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount

import phone_server as P
import vault_server as V

MCP_SECRET = os.environ.get("MCP_SECRET", "").strip()
VAULT_PASSWORD = os.environ.get("VAULT_PASSWORD", "")
_unlock_lock = threading.Lock()

mcp = FastMCP("Vault Library", instructions=(
    "Read-only access to the user's encrypted personal document vault. "
    "Use list_vault_files to locate a document, find_chapter to locate a section, "
    "read_pages to read selected PDF pages, and search_file to find relevant passages. "
    "Keep page ranges small."
), host="0.0.0.0", streamable_http_path="/",
   transport_security=TransportSecuritySettings(
       allowed_hosts=["vault-phone.onrender.com", "vault-phone.onrender.com:*"]
   ))


def _ensure_unlocked():
    """Unlock from Render environment or the existing durable worker key."""
    if V.KEY.get("aes") is not None:
        return
    with _unlock_lock:
        if V.KEY.get("aes") is not None:
            return
        P._load_leech_worker_key()
        if V.KEY.get("aes") is None:
            if not VAULT_PASSWORD:
                raise RuntimeError("Vault is locked. Set VAULT_PASSWORD in the Render environment.")
            from cryptography.hazmat.primitives.hashes import SHA256
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            raw = PBKDF2HMAC(SHA256(), 32, b"vault-v1", 300000).derive(VAULT_PASSWORD.encode())
            aes = AESGCM(raw)
            try:
                valid = P._load_library_cache(aes)
                if not valid:
                    valid = P.verify(aes)
            except Exception as exc:
                raise RuntimeError("Vault unlock check failed: " + str(exc)[:180]) from exc
            if not valid:
                raise RuntimeError("VAULT_PASSWORD did not unlock this vault.")
            V.clear_stream_state()
            V.KEY["aes"], V.KEY["raw"] = aes, raw
            P._persist_leech_worker_key(raw)
            P._save_library_cache()
        P.start_scan()
        P.start_meta_fill()


def _file(fid):
    _ensure_unlocked()
    fid = str(fid or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", fid):
        raise ValueError("Invalid file_id.")
    item = P.NAMES.get(fid) or next((x for x in P.library()["items"] if x.get("id") == fid), None)
    if not item:
        raise ValueError("File not found or its metadata is still indexing.")
    if not P._hydrate_cached_stream(fid):
        raise RuntimeError("File stream is not ready yet. Retry after the library index finishes.")
    info = V.get_info(fid)
    return item, info


def _read_pdf_page_text(reader, page_number):
    try:
        return (reader.pages[page_number - 1].extract_text() or "").strip()
    except Exception:
        return ""


def _pdf_reader(fid):
    item, info = _file(fid)
    if not (str(item.get("name", "")).lower().endswith(".pdf") or "pdf" in str(item.get("type", "")).lower()):
        raise ValueError("This file is not a PDF.")
    tmp = tempfile.TemporaryFile()
    try:
        for index in range(int(info["n"])):
            tmp.write(V.get_chunk(fid, index))
        tmp.seek(0)
        from pypdf import PdfReader
        reader = PdfReader(tmp, strict=False)
        return item, tmp, reader
    except Exception:
        tmp.close()
        raise


def _all_files():
    _ensure_unlocked()
    P.start_scan()
    return P.library()["items"]


@mcp.tool()
def list_vault_files(query: str = "", folder: str = "", limit: int = 100, offset: int = 0) -> str:
    """List indexed vault files. Optional case-insensitive filename/folder query and folder filter."""
    items = _all_files()
    q, folder_q = str(query or "").casefold(), str(folder or "").strip("/").casefold()
    if q:
        items = [x for x in items if q in str(x.get("name", "")).casefold()
                 or q in str(x.get("folder", "")).casefold()]
    if folder_q:
        items = [x for x in items if str(x.get("folder", "")).strip("/").casefold() == folder_q]
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    return json.dumps({"total": len(items), "offset": offset, "files": items[offset:offset + limit]},
                      ensure_ascii=False)


@mcp.tool()
def get_file_info(file_id: str) -> str:
    """Return metadata, file size, MIME type, and PDF page count when applicable."""
    item, info = _file(file_id)
    result = {k: item.get(k) for k in ("id", "name", "folder", "type", "size", "t", "ok")}
    result.update({"size_bytes": int(info["size"]), "mime_type": info.get("type", "")})
    if str(item.get("name", "")).lower().endswith(".pdf") or "pdf" in str(item.get("type", "")).lower():
        _, tmp, reader = _pdf_reader(file_id)
        try:
            result["page_count"] = len(reader.pages)
        finally:
            tmp.close()
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
def read_pages(file_id: str, start_page: int, end_page: int = 0) -> str:
    """Extract text from a PDF page range (1-based, inclusive; maximum 20 pages per call)."""
    item, tmp, reader = _pdf_reader(file_id)
    try:
        total = len(reader.pages)
        start = max(1, int(start_page))
        end = int(end_page) if int(end_page or 0) else start
        end = min(total, max(start, end))
        if end - start + 1 > 20:
            raise ValueError("Read at most 20 pages per call.")
        pages = [{"page": n, "text": _read_pdf_page_text(reader, n)} for n in range(start, end + 1)]
        return json.dumps({"file": item.get("name"), "page_count": total, "pages": pages},
                          ensure_ascii=False)
    finally:
        tmp.close()


@mcp.tool()
def search_file(file_id: str, query: str, max_results: int = 10) -> str:
    """Search PDF text page by page and return matching page snippets."""
    term = str(query or "").strip()
    if len(term) < 2:
        raise ValueError("Search query must contain at least two characters.")
    item, tmp, reader = _pdf_reader(file_id)
    try:
        matches = []
        needle = term.casefold()
        for n, page in enumerate(reader.pages, 1):
            text = (page.extract_text() or "").strip()
            pos = text.casefold().find(needle)
            if pos >= 0:
                matches.append({"page": n, "snippet": text[max(0, pos - 350):pos + len(term) + 650]})
                if len(matches) >= max(1, min(int(max_results), 30)):
                    break
        return json.dumps({"file": item.get("name"), "query": term, "matches": matches},
                          ensure_ascii=False)
    finally:
        tmp.close()


@mcp.tool()
def find_chapter(file_id: str, chapter: str, max_results: int = 12) -> str:
    """Find chapter/section headings in a PDF by matching the supplied title or number."""
    term = str(chapter or "").strip()
    if not term:
        raise ValueError("Provide a chapter title or number.")
    item, tmp, reader = _pdf_reader(file_id)
    try:
        matches = []
        needle = term.casefold()
        cap = max(1, min(int(max_results), 30))
        for n, page in enumerate(reader.pages, 1):
            lines = [line.strip() for line in (page.extract_text() or "").splitlines() if line.strip()]
            for line in lines:
                if needle in line.casefold() and len(line) <= 240:
                    matches.append({"page": n, "heading": line})
                    if len(matches) >= cap:
                        break
            if len(matches) >= cap:
                break
        return json.dumps({"file": item.get("name"), "chapter_query": term, "matches": matches},
                          ensure_ascii=False)
    finally:
        tmp.close()


@mcp.tool()
def read_vault_file(file_id: str, max_chars: int = 12000) -> str:
    """Read a text-based vault file, or the first few pages of a PDF as extracted text."""
    item, info = _file(file_id)
    max_chars = max(500, min(int(max_chars), 30000))
    name = str(item.get("name", ""))
    if name.lower().endswith(".pdf") or "pdf" in str(item.get("type", "")).lower():
        _, tmp, reader = _pdf_reader(file_id)
        try:
            parts, used = [], 0
            for n in range(1, len(reader.pages) + 1):
                page_text = _read_pdf_page_text(reader, n)
                if page_text:
                    part = f"\n--- Page {n} ---\n{page_text}"
                    parts.append(part)
                    used += len(part)
                    if used >= max_chars:
                        break
            return f"File: {name}\n" + "".join(parts)[:max_chars]
        finally:
            tmp.close()
    if not re.search(r"\.(txt|md|csv|json|html|xml|rtf|log)$", name, re.I):
        raise ValueError("This format is not supported for text extraction. For PDFs, use read_pages.")
    data = bytearray()
    for index in range(int(info["n"])):
        data.extend(V.get_chunk(file_id, index))
        if len(data) >= max_chars * 4:
            break
    return bytes(data[:max_chars * 4]).decode("utf-8", errors="replace")[:max_chars]


class MCPPathRouter:
    """Intercept /mcp/<secret> before Starlette routing and normalize it for FastMCP."""
    def __init__(self, app, mcp_app):
        self.app = app
        self.mcp_app = mcp_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and str(scope.get("path", "")).startswith("/mcp/"):
            parts = str(scope.get("path", "")).split("/")
            supplied = parts[2] if len(parts) == 3 else ""
            if not MCP_SECRET or not hmac.compare_digest(supplied, MCP_SECRET):
                response = PlainTextResponse("Not found", status_code=404)
                await response(scope, receive, send)
                return
            child_scope = dict(scope)
            child_scope["path"] = "/"
            child_scope["raw_path"] = b"/"
            child_scope["root_path"] = ""
            await self.mcp_app(child_scope, receive, send)
            return
        await self.app(scope, receive, send)


def create_asgi_app(flask_app):
    if not MCP_SECRET:
        print("MCP disabled: set MCP_SECRET to enable the private connector endpoint.", flush=True)
    mcp_asgi = mcp.streamable_http_app()

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            yield

    flask_asgi = Starlette(
        routes=[Mount("/", app=WSGIMiddleware(flask_app))],
        lifespan=lifespan,
    )
    return MCPPathRouter(flask_asgi, mcp_asgi)
