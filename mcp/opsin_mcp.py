"""OPSIN connector with bounded, persistent storage for public PNG depictions."""

import asyncio
import base64
from contextlib import closing
from hashlib import sha256
from hmac import compare_digest
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import unicodedata
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import RequestBodyLimitMiddleware, TransportSecuritySettings
from mcp.types import ImageContent, TextContent, ToolAnnotations
from pydantic import Field
from rdkit import Chem, rdBase
from rdkit.Chem.Draw import rdMolDraw2D
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route
import uvicorn

from opsin_oauth import OpsinOAuth

JAR_PATH = Path(os.environ.get("OPSIN_JAR", Path(__file__).resolve().parents[1] /
                               "opsin-cli/target/opsin-cli-3.0-SNAPSHOT-jar-with-dependencies.jar"))
PARSER_TIMEOUT = 15
_slot = asyncio.Lock()
_BANNER = "Run the jar using the -h flag for help. Enter a chemical name to begin:"
# ChatGPT connectors drop MCP image blocks, so renderings stay addressable by URL.
_DEPICTION_TTL = 7 * 24 * 60 * 60
_DEPICTION_MAX_BYTES = 256 * 1024 * 1024
_DEPICTION_PATH = re.compile(r"/depict/[0-9a-f]{32}\.png")


def _depiction_db() -> sqlite3.Connection:
    oauth_db = Path(os.environ.get("OPSIN_OAUTH_DB", Path(__file__).resolve().parent / ".oauth" / "tokens.sqlite3"))
    path = Path(os.environ.get("OPSIN_DEPICTION_DB", oauth_db.with_name("depictions.sqlite3")))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    try:
        path.chmod(0o600)
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        db.execute(f"PRAGMA max_page_count = {_DEPICTION_MAX_BYTES // page_size}")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS depictions (key TEXT PRIMARY KEY, png BLOB NOT NULL, expires REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS depiction_expiry ON depictions(expires);
        """)
    except BaseException:
        db.close()
        raise
    return db


def _publish(png: bytes) -> str:
    digest = sha256(png).hexdigest()[:32]
    try:
        with closing(_depiction_db()) as db:
            # Commit cleanup separately so a full-database rollback cannot restore expired images.
            with db:
                db.execute("DELETE FROM depictions WHERE expires <= ?", (time.time(),))
            with db:
                db.execute("""INSERT INTO depictions (key, png, expires) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET expires = excluded.expires""",
                           (digest, png, time.time() + _DEPICTION_TTL))
    except (OSError, sqlite3.Error) as exc:
        raise ToolError("Image storage is full or unavailable. Try again later.") from exc
    return f"https://{os.environ.get('PUBLIC_HOST', 'localhost')}/depict/{digest}.png"


async def smiles_for_name(name: str) -> tuple[str, str]:
    """One bounded Java process per name; never invoke a shell or interpret input as flags."""
    try:
        process = await asyncio.create_subprocess_exec(
            "java", "-Xmx128m", "-XX:ActiveProcessorCount=1", "-jar", str(JAR_PATH), "-o", "extendedsmi",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise ToolError("OPSIN is unavailable. Try again later.") from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate((name + "\n").encode()), PARSER_TIMEOUT)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise ToolError("OPSIN timed out. Try a shorter or simpler systematic name.") from exc
    warnings = stderr.decode("utf-8", errors="replace").replace(_BANNER, "").strip()[:2000]
    smiles = stdout.decode("utf-8", errors="replace").strip()
    if process.returncode or not smiles or "\n" in smiles or len(smiles) > 16384:
        raise ToolError("OPSIN could not interpret this systematic chemical name.")
    smiles, _, extension = smiles.partition(" |")
    # OPSIN's racemic marker is ignored by RDKit; never depict these groups as absolute.
    if re.search(r"(?:^|,)(?:r(?:,|\|)|[&o]\d+:)", extension):
        raise ToolError("Depiction of racemic or relative stereochemistry is not supported; no structure was rendered.")
    return smiles, warnings


async def depict_chemical(
    name: Annotated[str, Field(min_length=1, max_length=256, description="One systematic chemical name, not SMILES or a file path.")],
    include_svg: bool = False,
) -> list[TextContent | ImageContent]:
    """Parse a systematic chemical name with OPSIN and return SMILES plus a visible 2D PNG.

    Optionally include SVG source as text. The PNG, not the SVG, is the model-readable
    image. Not all common or trade names are supported. Warnings must be reported.
    Racemic and relative stereochemistry are rejected rather than depicted as absolute.
    Public image URLs expire seven days after their last generation.
    Public service: do not submit confidential structures. No chemical safety assessment.
    """
    if not name.strip() or len(name) > 256 or any(unicodedata.category(c).startswith("C") or
                                                unicodedata.category(c) in ("Zl", "Zp") for c in name):
        raise ToolError("Provide one nonempty chemical name, at most 256 characters, without control characters.")
    if _slot.locked():
        raise ToolError("Structure service is busy. Try again shortly.")
    async with _slot:
        smiles, warnings = await smiles_for_name(name.strip())
        with rdBase.BlockLogs():
            molecule = Chem.MolFromSmiles(smiles)
        if molecule is None or molecule.GetNumAtoms() == 0:
            raise ToolError("OPSIN returned a structure that cannot be depicted.")
        if molecule.GetNumAtoms() > 100:
            raise ToolError("Structure exceeds the 100-atom depiction limit.")
        try:
            png = rdMolDraw2D.MolDraw2DCairo(640, 480)
            rdMolDraw2D.PrepareAndDrawMolecule(png, molecule)
            png.FinishDrawing()
            drawing = png.GetDrawingText()
            metadata = {"name": name.strip(), "smiles": smiles, "warnings": warnings or None,
                        "image_url": _publish(drawing)}
            content: list[TextContent | ImageContent] = [
                TextContent(type="text", text=json.dumps(metadata, ensure_ascii=False)),
                ImageContent(type="image", mimeType="image/png", data=base64.b64encode(drawing).decode("ascii")),
            ]
            if include_svg:
                svg = rdMolDraw2D.MolDraw2DSVG(640, 480)
                rdMolDraw2D.PrepareAndDrawMolecule(svg, molecule)
                svg.FinishDrawing()
                content.append(TextContent(type="text", text=svg.GetDrawingText()))
        except (ValueError, RuntimeError) as exc:
            raise ToolError("Unable to draw this structure.") from exc
        if len(json.dumps([part.model_dump() for part in content])) > 140_000:
            raise ToolError("Depiction is too large. Retry without SVG or with a smaller molecule.")
        return content


def create_app() -> Starlette:
    key = os.environ.get("OPSIN_API_KEY")
    if not key:
        raise RuntimeError("OPSIN_API_KEY must be set and nonempty")
    api_key = key.encode("utf-8")
    public_host = os.environ.get("PUBLIC_HOST", "localhost")
    issuer_url = f"https://{public_host}"
    oauth = OpsinOAuth(key, issuer_url, Path(os.environ.get(
        "OPSIN_OAUTH_DB", Path(__file__).resolve().parent / ".oauth" / "tokens.sqlite3",
    )))
    oauth_routes = oauth.routes()
    public_paths = {"/healthz", *(route.path for route in oauth_routes)}

    async def require_credentials(request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Cloudflare terminates TLS before Coolify's private HTTP origin.
        visitor = request.headers.getlist("cf-visitor")
        is_https = (
            bool(re.fullmatch(r'\s*\{\s*"scheme"\s*:\s*"https"\s*\}\s*', visitor[0]))
            if len(visitor) == 1 else not visitor and request.url.scheme == "https"
        )
        if request.url.path != "/healthz" and not is_https:
            target = issuer_url + request.url.path + ("?" + request.url.query if request.url.query else "")
            return RedirectResponse(target, status_code=307, headers={"Cache-Control": "no-store"})
        if request.url.path not in public_paths and not _DEPICTION_PATH.fullmatch(request.url.path):
            authorization = request.headers.getlist("authorization")
            bearer = (
                re.fullmatch(r"Bearer +([A-Za-z0-9._~+/-]+=*)", authorization[0], re.IGNORECASE | re.ASCII)
                if len(authorization) == 1 else None
            )
            if bearer is None or not (
                compare_digest(bearer[1].encode("ascii"), api_key) or await oauth.verify_token(bearer[1])
            ):
                return Response(status_code=401, headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{issuer_url}/.well-known/oauth-protected-resource/mcp"',
                    "Cache-Control": "no-store",
                })
        response = await call_next(request)
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    server = FastMCP(
        "OPSIN", instructions="Convert systematic chemical names to structures. Read the inline PNG and show the image_url "
        "link so the user can see the drawing. Report any warnings.",
        host="0.0.0.0", port=8080, stateless_http=True, json_response=True,
        max_request_body_size=8192, log_level="WARNING",
        transport_security=TransportSecuritySettings(
            allowed_hosts=[public_host, "localhost:*", "127.0.0.1:*"],
            allowed_origins=[f"https://{public_host}"],
        ),
    )
    server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                                           openWorldHint=False), structured_output=False)(depict_chemical)

    @server.custom_route("/healthz", methods=["GET"])
    async def health(_request: Request) -> JSONResponse:
        ready = JAR_PATH.is_file()
        return JSONResponse({"status": "ok" if ready else "unavailable"}, status_code=200 if ready else 503)

    @server.custom_route("/depict/{key}.png", methods=["GET"])
    async def depiction(request: Request) -> Response:
        try:
            with closing(_depiction_db()) as db:
                with db:
                    db.execute("DELETE FROM depictions WHERE expires <= ?", (time.time(),))
                row = db.execute("SELECT png, expires FROM depictions WHERE key = ? AND expires > ?",
                                 (request.path_params["key"], time.time())).fetchone()
        except (OSError, sqlite3.Error):
            return Response(status_code=503, headers={"Cache-Control": "no-store"})
        if row is None:
            return Response(status_code=404, headers={"Cache-Control": "no-store"})
        max_age = min(3600, max(0, int(row[1] - time.time())))
        return Response(row[0], media_type="image/png", headers={"Cache-Control": f"public, max-age={max_age}"})

    async def reject_sse(_request: Request) -> Response:
        return Response(status_code=405, headers={"Allow": "POST, DELETE"})

    app = server.streamable_http_app()
    app.add_middleware(BaseHTTPMiddleware, dispatch=require_credentials)
    app.add_middleware(RequestBodyLimitMiddleware, max_body_size=8192)
    app.routes.extend(oauth_routes)
    # Stateless JSON responses need no standalone SSE channel.
    app.routes.insert(0, Route("/mcp", reject_sse, methods=["GET"]))
    return app


if __name__ == "__main__":
    if not JAR_PATH.is_file():
        raise SystemExit("OPSIN_JAR must point to a built OPSIN CLI jar")
    uvicorn.run(create_app(), host="0.0.0.0", port=8080, log_level="warning")
