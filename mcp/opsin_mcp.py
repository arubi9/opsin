"""Stateless OPSIN connector. The PNG content block is sent directly to model vision."""

import asyncio
import base64
from hmac import compare_digest
import json
import os
from pathlib import Path
import re
import unicodedata
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ImageContent, TextContent, ToolAnnotations
from pydantic import Field
from rdkit import Chem, rdBase
from rdkit.Chem.Draw import rdMolDraw2D
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

JAR_PATH = Path(os.environ.get("OPSIN_JAR", Path(__file__).resolve().parents[1] /
                               "opsin-cli/target/opsin-cli-3.0-SNAPSHOT-jar-with-dependencies.jar"))
PARSER_TIMEOUT = 15
_slot = asyncio.Lock()
_BANNER = "Run the jar using the -h flag for help. Enter a chemical name to begin:"


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
            metadata = {"name": name.strip(), "smiles": smiles, "warnings": warnings or None}
            content: list[TextContent | ImageContent] = [
                TextContent(type="text", text=json.dumps(metadata, ensure_ascii=False)),
                ImageContent(type="image", mimeType="image/png", data=base64.b64encode(png.GetDrawingText()).decode("ascii")),
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

    async def require_api_key(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path != "/healthz":
            authorization = request.headers.getlist("authorization")
            bearer = (
                re.fullmatch(r"Bearer +([A-Za-z0-9._~+/-]+=*)", authorization[0], re.IGNORECASE | re.ASCII)
                if len(authorization) == 1 else None
            )
            if bearer is None or not compare_digest(bearer[1].encode("ascii"), api_key):
                return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)

    public_host = os.environ.get("PUBLIC_HOST", "localhost")
    server = FastMCP(
        "OPSIN", instructions="Convert systematic chemical names to structures. Read the inline PNG and report any warnings.",
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

    async def reject_sse(_request: Request) -> Response:
        return Response(status_code=405, headers={"Allow": "POST, DELETE"})

    app = server.streamable_http_app()
    app.add_middleware(BaseHTTPMiddleware, dispatch=require_api_key)
    # Stateless JSON responses need no standalone SSE channel.
    app.routes.insert(0, Route("/mcp", reject_sse, methods=["GET"]))
    return app


if __name__ == "__main__":
    if not JAR_PATH.is_file():
        raise SystemExit("OPSIN_JAR must point to a built OPSIN CLI jar")
    uvicorn.run(create_app(), host="0.0.0.0", port=8080, log_level="warning")
