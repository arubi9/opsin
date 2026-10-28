import asyncio
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import AsyncMock
import xml.etree.ElementTree as ET

import httpx
import pytest
from PIL import Image
from mcp.server.fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

import opsin_mcp as service


TEST_API_KEY = "test-only-opsin-api-key"


@pytest.fixture(autouse=True)
def api_key(monkeypatch, tmp_path):
    monkeypatch.setenv("OPSIN_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("OPSIN_OAUTH_DB", str(tmp_path / "oauth" / "tokens.sqlite3"))
    monkeypatch.setenv("OPSIN_DEPICTION_DB", str(tmp_path / "depictions" / "images.sqlite3"))


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PUBLIC_HOST", "testserver")
    with TestClient(service.create_app(), base_url="https://testserver", headers={"Authorization": f"Bearer {TEST_API_KEY}"}) as client:
        yield client


def rpc(client, method, params=None, **kwargs):
    return client.post("/mcp", headers={"Accept": "application/json, text/event-stream"},
                       json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, **kwargs)


@pytest.mark.parametrize("key", [None, ""])
def test_startup_requires_nonempty_api_key(monkeypatch, key):
    if key is None:
        monkeypatch.delenv("OPSIN_API_KEY", raising=False)
    else:
        monkeypatch.setenv("OPSIN_API_KEY", key)
    with pytest.raises(RuntimeError, match="OPSIN_API_KEY"):
        service.create_app()


@pytest.mark.parametrize("authorization", [
    None, "", "Basic not-a-bearer-token", "Bearer", "Bearer ", "Bearer wrong-key",
    f"Bearer {TEST_API_KEY} extra", f"Bearer {TEST_API_KEY},other-token",
    f"Bearer\t{TEST_API_KEY}", f"Bearer {TEST_API_KEY}\n", b"Bearer \xff", b"Bearer \xe2\x98\x83",
])
def test_unauthorized_requests_never_reach_parser(client, monkeypatch, caplog, authorization):
    parser = AsyncMock(return_value=("CCO", ""))
    monkeypatch.setattr(service, "smiles_for_name", parser)
    client.headers.pop("Authorization")
    if authorization is not None:
        client.headers.update({"Authorization": authorization})
    response = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": "ethanol"}})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer ")
    parser.assert_not_called()
    assert TEST_API_KEY not in response.text + caplog.text
    assert "wrong-key" not in response.text + caplog.text


@pytest.mark.parametrize("prefix", ["Bearer ", "bEaReR ", "Bearer   "])
def test_correct_bearer_reaches_parser(client, monkeypatch, prefix):
    parser = AsyncMock(return_value=("CCO", ""))
    monkeypatch.setattr(service, "smiles_for_name", parser)
    client.headers["Authorization"] = prefix + TEST_API_KEY
    response = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": "ethanol"}})
    assert response.status_code == 200
    assert not response.json()["result"].get("isError")
    parser.assert_awaited_once_with("ethanol")


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/mcp"), ("GET", "/mcp?probe=1"), ("DELETE", "/mcp"),
    ("OPTIONS", "/mcp"), ("GET", "/unknown"), ("GET", "/healthz/"),
])
def test_all_other_paths_require_bearer(client, method, path):
    client.headers.pop("Authorization")
    response = client.request(method, path)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer ")


def test_duplicate_authorization_headers_rejected(client, monkeypatch):
    parser = AsyncMock(return_value=("CCO", ""))
    monkeypatch.setattr(service, "smiles_for_name", parser)
    client.headers.pop("Authorization")
    response = client.post("/mcp", headers=[
        ("Accept", "application/json, text/event-stream"),
        ("Authorization", f"Bearer {TEST_API_KEY}"), ("Authorization", "Bearer wrong-key"),
    ], json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "depict_chemical", "arguments": {"name": "ethanol"}}})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer ")
    parser.assert_not_called()


@pytest.mark.parametrize("authorization", [None, "Bearer wrong-key"])
def test_health_is_unauthenticated(client, authorization):
    client.headers.pop("Authorization")
    if authorization is not None:
        client.headers["Authorization"] = authorization
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.parametrize("path", ["/mcp", "/authorize", "/oauth/consent", "/register", "/token", "/revoke"])
def test_cleartext_requests_redirect_to_configured_https_origin(monkeypatch, path):
    monkeypatch.setenv("PUBLIC_HOST", "testserver")
    with TestClient(service.create_app(), base_url="http://testserver", follow_redirects=False) as cleartext:
        response = cleartext.get(path + "?state=opaque", headers={"Host": "untrusted.example"})
        assert response.status_code == 307
        assert response.headers["location"] == "https://testserver" + path + "?state=opaque"
        assert response.headers["Cache-Control"] == "no-store"
        assert cleartext.get("/healthz").status_code in (200, 503)


@pytest.mark.parametrize("visitor", ['{"scheme":"https"}', '{ "scheme" : "https" }'])
def test_cloudflare_tls_termination_keeps_oauth_working(monkeypatch, visitor):
    monkeypatch.setenv("PUBLIC_HOST", "testserver")
    with TestClient(service.create_app(), base_url="http://testserver", follow_redirects=False) as origin:
        response = origin.get("/.well-known/oauth-authorization-server", headers={"CF-Visitor": visitor})
        assert response.status_code == 200
        assert response.headers["Strict-Transport-Security"] == "max-age=31536000"


@pytest.mark.parametrize("visitor", ['{"scheme":"http"}', "invalid", '{"scheme":"https","other":1}'])
def test_insecure_or_malformed_edge_scheme_does_not_bypass_https(monkeypatch, visitor):
    monkeypatch.setenv("PUBLIC_HOST", "testserver")
    with TestClient(service.create_app(), base_url="http://testserver", follow_redirects=False) as origin:
        response = origin.get("/authorize", headers={"CF-Visitor": visitor})
        assert response.status_code == 307
        assert response.headers["location"] == "https://testserver/authorize"


def test_oauth_discovery_is_public_and_uses_configured_origin(client):
    client.headers.pop("Authorization")
    resource = client.get("/.well-known/oauth-protected-resource/mcp", headers={"Host": "untrusted.example"})
    assert resource.status_code == 200
    assert resource.json()["resource"] == "https://testserver/mcp"
    assert [issuer.rstrip("/") for issuer in resource.json()["authorization_servers"]] == ["https://testserver"]
    assert resource.json()["scopes_supported"] == ["opsin:depict"]
    discovery = client.get("/.well-known/oauth-authorization-server")
    assert discovery.status_code == 200
    metadata = discovery.json()
    assert metadata["issuer"].rstrip("/") == "https://testserver"
    assert metadata["authorization_endpoint"] == "https://testserver/authorize"
    assert metadata["token_endpoint"] == "https://testserver/token"
    assert metadata["registration_endpoint"] == "https://testserver/register"
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert TEST_API_KEY not in resource.text + discovery.text


def test_unauthorized_mcp_advertises_oauth_discovery_without_disabling_auth(client, monkeypatch):
    parser = AsyncMock()
    monkeypatch.setattr(service, "smiles_for_name", parser)
    client.headers.pop("Authorization")
    response = rpc(client, "tools/list")
    assert response.status_code == 401
    assert 'resource_metadata="https://testserver/.well-known/oauth-protected-resource/mcp"' in response.headers["WWW-Authenticate"]
    assert response.headers["Cache-Control"] == "no-store"
    parser.assert_not_called()


@pytest.mark.parametrize("path", ["/register", "/token", "/oauth/consent"])
def test_public_oauth_endpoints_keep_request_body_limit(client, path):
    client.headers.pop("Authorization")
    response = client.post(path, content=b"x" * 8193)
    assert response.status_code == 413


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


def test_linked_png_is_public_and_served_as_image(client, monkeypatch):
    monkeypatch.setattr(service, "smiles_for_name", AsyncMock(return_value=("CCO", "")))
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": "ethanol"}}).json()["result"]
    url = json.loads(result["content"][0]["text"])["image_url"]
    assert url.startswith("https://testserver/depict/")
    client.headers.pop("Authorization")
    served = client.get(url.split("testserver", 1)[1])
    assert served.status_code == 200
    assert served.headers["content-type"] == "image/png"
    assert served.content == base64.b64decode(result["content"][1]["data"], validate=True)
    assert client.get("/depict/" + "0" * 32 + ".png").status_code == 404
    assert client.get("/depict/not-a-digest.png").status_code == 401


def test_depiction_survives_publisher_process_exit(client):
    publisher = subprocess.run(
        [sys.executable, "-c", "import opsin_mcp; print(opsin_mcp._publish(b'persisted depiction'))"],
        cwd=Path(service.__file__).parent, capture_output=True, text=True, check=True,
    )
    client.headers.pop("Authorization")
    response = client.get(publisher.stdout.strip())
    assert response.status_code == 200
    assert response.content == b"persisted depiction"


def test_depictions_are_not_evicted_after_64_images(client):
    url = service._publish(b"first depiction")
    for i in range(70):
        service._publish(f"depiction {i}".encode())
    assert client.get(url).content == b"first depiction"


def test_depiction_expires_after_seven_days(client, monkeypatch):
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    url = service._publish(b"expiring depiction")
    now += 7 * 24 * 60 * 60 - 30
    response = client.get(url)
    assert response.status_code == 200
    max_age = int(response.headers["cache-control"].split("max-age=")[1])
    assert 0 <= max_age <= 30
    now += 30
    response = client.get(url)
    assert response.status_code == 404
    assert response.headers["cache-control"] == "no-store"


def test_republishing_refreshes_expiry(client, monkeypatch):
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    url = service._publish(b"reused depiction")
    now += 6 * 24 * 60 * 60
    assert service._publish(b"reused depiction") == url
    now += 2 * 24 * 60 * 60
    assert client.get(url).content == b"reused depiction"


def test_depiction_storage_is_bounded_and_expired_space_is_reused(client, monkeypatch):
    monkeypatch.setattr(service, "_DEPICTION_MAX_BYTES", 64 * 1024, raising=False)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    url = service._publish(b"keep this image")
    for _ in range(20):
        try:
            service._publish(os.urandom(8192))
        except ToolError as exc:
            assert "storage" in str(exc).lower()
            break
    else:
        pytest.fail("Image storage exceeded its capacity without rejecting publication")
    assert Path(os.environ["OPSIN_DEPICTION_DB"]).stat().st_size <= 64 * 1024
    assert client.get(url).content == b"keep this image"
    now += 7 * 24 * 60 * 60
    new_url = service._publish(b"new depiction after cleanup")
    assert client.get(new_url).content == b"new depiction after cleanup"
    assert client.get(url).status_code == 404
    assert Path(os.environ["OPSIN_DEPICTION_DB"]).stat().st_size <= 64 * 1024


def test_depiction_storage_errors_are_reported(client, monkeypatch, tmp_path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("blocked")
    monkeypatch.setenv("OPSIN_DEPICTION_DB", str(blocker / "images.sqlite3"))
    monkeypatch.setattr(service, "smiles_for_name", AsyncMock(return_value=("CCO", "")))
    result = rpc(client, "tools/call", {"name": "depict_chemical", "arguments": {"name": "ethanol"}}).json()["result"]
    assert result["isError"]
    assert "storage" in result["content"][0]["text"].lower()
    response = client.get("/depict/" + "0" * 32 + ".png")
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"


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
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://localhost",
                                     headers={"Authorization": f"Bearer {TEST_API_KEY}"}) as client:
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
