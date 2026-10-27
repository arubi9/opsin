import asyncio
import base64
import io
import json
import os
from unittest.mock import AsyncMock
import xml.etree.ElementTree as ET

import httpx
import pytest
from PIL import Image
from mcp.server.fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

import opsin_mcp as service


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PUBLIC_HOST", "testserver")
    with TestClient(service.create_app()) as client:
        yield client


def rpc(client, method, params=None, **kwargs):
    return client.post("/mcp", headers={"Accept": "application/json, text/event-stream"},
                       json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, **kwargs)


def test_initialize_and_schema(client):
    response = rpc(client, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "test", "version": "1"}})
    assert response.status_code == 200
    assert "tools" in response.json()["result"]["capabilities"]
    tools = rpc(client, "tools/list").json()["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["depict_chemical"]
    assert tools[0]["annotations"]["readOnlyHint"] is True
    assert tools[0]["inputSchema"]["properties"]["name"]["maxLength"] == 256


def test_image_and_optional_svg_reach_mcp_content(client, monkeypatch):
    monkeypatch.setattr(service, "smiles_for_name", AsyncMock(return_value=("CCO", "")))
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {
        "name": "ethanol", "include_svg": True}}).json()["result"]
    assert not result.get("isError")
    content = result["content"]
    assert "CCO" in content[0]["text"]
    assert content[1]["type"] == "image"
    assert content[1]["mimeType"] == "image/png"
    image = Image.open(io.BytesIO(base64.b64decode(content[1]["data"], validate=True)))
    assert image.size == (640, 480)
    darkest = image.convert("L").getextrema()[0]
    assert isinstance(darkest, (int, float))
    assert image.getbbox() and darkest < 200
    assert ET.fromstring(content[2]["text"]).tag.endswith("svg")
    assert len(str(result)) < 150_000


def test_default_is_png_not_svg(client, monkeypatch):
    monkeypatch.setattr(service, "smiles_for_name", AsyncMock(return_value=("CCO", "")))
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": "ethanol"}}).json()["result"]
    assert [part["type"] for part in result["content"]] == ["text", "image"]


@pytest.mark.parametrize("name", ["", "  ", "a" * 257, "ethanol\nmethane", "ethanol\x00", "ethanol\r", "ethanol\u2028methane"])
def test_invalid_names_never_reach_parser(client, monkeypatch, name):
    parser = AsyncMock()
    monkeypatch.setattr(service, "smiles_for_name", parser)
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": name}}).json()["result"]
    assert result["isError"]
    parser.assert_not_called()


def test_warnings_not_silently_discarded(client, monkeypatch):
    monkeypatch.setattr(service, "smiles_for_name", AsyncMock(return_value=("CCO", "Ambiguous name")))
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": "ethanol"}}).json()["result"]
    assert "Ambiguous name" in result["content"][0]["text"]


@pytest.mark.parametrize("smiles", ["bad smiles", "C" * 101])
def test_undrawable_or_oversized_molecule_is_tool_error(client, monkeypatch, smiles):
    monkeypatch.setattr(service, "smiles_for_name", AsyncMock(return_value=(smiles, "")))
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": "ethanol"}}).json()["result"]
    assert result["isError"]
    assert not any(part["type"] == "image" for part in result["content"])


def test_host_origin_and_body_limits(client):
    assert client.get("/healthz").status_code == 200
    assert client.post("/mcp", headers={"Host": "evil.example", "Accept": "application/json, text/event-stream"},
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 421
    assert client.post("/mcp", headers={"Origin": "https://evil.example", "Accept": "application/json, text/event-stream"},
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).status_code == 403
    assert client.post("/mcp", content=b"x" * 8193,
                       headers={"Accept": "application/json, text/event-stream"}).status_code == 413
    assert client.post("/mcp", content=iter([b"x" * 4096, b"y" * 4097]),
                       headers={"Accept": "application/json, text/event-stream"}).status_code == 413


@pytest.mark.parametrize("path", ["/mcp", "/mcp?probe=1"])
async def test_stateless_endpoint_rejects_standalone_sse(path):
    app = service.create_app()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            try:
                response = await asyncio.wait_for(
                    client.get(path, headers={"Accept": "text/event-stream"}), timeout=1,
                )
            except TimeoutError:
                pytest.fail("GET /mcp must return 405 instead of holding open an SSE connection")
            assert response.status_code == 405
            assert "POST" in response.headers["allow"]
            response = await client.post("/mcp", headers={"Accept": "application/json, text/event-stream"},
                                         json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert response.status_code == 200


@pytest.mark.parametrize("extension", ["r", "o1:1,3", "&1:1,3", "a:1,&1:3", "o1:1,&1:3"])
async def test_parser_rejects_nonabsolute_stereo_before_discarding_cxsmiles(monkeypatch, extension):
    process = AsyncMock()
    process.returncode = 0
    output = f"Cl[C@H](C)[C@@H](C)Cl |$_AV:Cl;2;1;3;4;Cl'$," + extension + "|"
    process.communicate.return_value = (output.encode(), b"")
    monkeypatch.setattr(service.asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    with pytest.raises(ToolError, match="racemic or relative stereochemistry"):
        await service.smiles_for_name("stereochemical name")


async def test_busy_gate_rejects_second_call(monkeypatch):
    started, release = asyncio.Event(), asyncio.Event()

    async def parse(_name):
        started.set()
        await release.wait()
        return "CCO", ""

    monkeypatch.setattr(service, "smiles_for_name", parse)
    first = asyncio.create_task(service.depict_chemical("ethanol"))
    await started.wait()
    try:
        with pytest.raises(ToolError, match="busy"):
            await service.depict_chemical("methane")
    finally:
        release.set()
        await first


async def test_timeout_kills_and_reaps_parser(monkeypatch):
    process = AsyncMock()
    process.kill = lambda: None
    process.communicate.side_effect = asyncio.TimeoutError
    monkeypatch.setattr(service.asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    with pytest.raises(ToolError, match="timed out"):
        await service.smiles_for_name("ethanol")
    process.wait.assert_awaited_once()


async def test_cancel_kills_and_reaps_parser(monkeypatch):
    process = AsyncMock()
    process.kill = lambda: None
    process.communicate.side_effect = asyncio.CancelledError
    monkeypatch.setattr(service.asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    with pytest.raises(asyncio.CancelledError):
        await service.smiles_for_name("ethanol")
    process.wait.assert_awaited_once()


@pytest.mark.skipif(not os.environ.get("OPSIN_JAR"), reason="set OPSIN_JAR to exercise real Java parser")
@pytest.mark.parametrize("name", [
    "rac-(2R,3R)-2,3-dichlorobutane",
    "rel-(2R,3R)-2,3-dichlorobutane",
    "rac-(R)-chlorofluorobromomethane",
    "rel-(R)-chlorofluorobromomethane",
])
def test_real_opsin_nonabsolute_stereo_is_explicit_tool_error(client, name):
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": name}}).json()["result"]
    assert result.get("isError")
    assert "racemic or relative stereochemistry" in result["content"][0]["text"]
    assert not any(part["type"] == "image" for part in result["content"])


@pytest.mark.skipif(not os.environ.get("OPSIN_JAR"), reason="set OPSIN_JAR to exercise real Java parser")
async def test_real_opsin_png_svg_and_bad_name():
    for name in ["ethanol", "(2R)-2-hydroxypropanoic acid", "(2R,3R)-2,3-dichlorobutane", "sodium chloride"]:
        result = await service.depict_chemical(name, include_svg=True)
        metadata = result[0]
        assert metadata.type == "text"
        smiles = json.loads(metadata.text)["smiles"]
        assert "|" not in smiles
        if name == "(2R,3R)-2,3-dichlorobutane":
            assert smiles == "Cl[C@H](C)[C@@H](C)Cl"
        assert result[1].type == "image"
        assert base64.b64decode(result[1].data).startswith(b"\x89PNG")
        svg = result[2]
        assert svg.type == "text"
        assert ET.fromstring(svg.text).tag.endswith("svg")
    with pytest.raises(ToolError):
        await service.depict_chemical("definitely not a chemical name")
