"""Exercise the actual OAuth routes and MCP authentication together."""

import base64
import hashlib
import secrets
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from starlette.testclient import TestClient

import opsin_mcp as service


class ConsentForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        name, value = attributes.get("name"), attributes.get("value")
        if name and value and (
            tag == "input" and attributes.get("type") == "hidden"
            or tag == "button" and value in ("approve", "allow")
        ):
            self.fields[name] = value


def test_real_oauth_tokens_authorize_mcp_and_survive_app_restart(monkeypatch, tmp_path):
    key = "integration-owner-api-key"
    monkeypatch.setenv("OPSIN_API_KEY", key)
    monkeypatch.setenv("PUBLIC_HOST", "testserver")
    monkeypatch.setenv("OPSIN_OAUTH_DB", str(tmp_path / "oauth" / "tokens.sqlite3"))
    callback = "https://chatgpt.com/connector_platform_oauth_redirect"
    resource = "https://testserver/mcp"
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    with TestClient(service.create_app(), base_url="https://testserver") as client:
        registration = client.post("/register", json={
            "client_name": "ChatGPT integration test", "redirect_uris": [callback],
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post", "scope": "opsin:depict",
        })
        assert registration.status_code == 201
        credentials = registration.json()
        consent = client.get("/authorize", params={
            "client_id": credentials["client_id"], "redirect_uri": callback,
            "response_type": "code", "scope": "opsin:depict", "resource": resource,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": "integration-state",
        })
        assert consent.status_code == 200
        form = ConsentForm()
        form.feed(consent.text)
        approved = client.post("/oauth/consent", data={**form.fields, "api_key": key}, follow_redirects=False)
        assert approved.status_code in (302, 303)
        callback_url = urlsplit(approved.headers["location"])
        assert callback_url.scheme == "https" and callback_url.netloc == "chatgpt.com"
        query = parse_qs(callback_url.query)
        assert query["state"] == ["integration-state"]
        tokens = client.post("/token", data={
            "grant_type": "authorization_code", "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"], "redirect_uri": callback,
            "code": query["code"][0], "code_verifier": verifier, "resource": resource,
        })
        assert tokens.status_code == 200
        access_token = tokens.json()["access_token"]
        assert access_token != key
    # A new app instance reads the same durable database, not an in-memory token map.
    with TestClient(service.create_app(), base_url="https://testserver") as restarted:
        for bearer in (access_token, key):
            response = restarted.post("/mcp", headers={
                "Authorization": f"Bearer {bearer}", "Accept": "application/json, text/event-stream",
            }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert response.status_code == 200
            assert response.json()["result"]["tools"][0]["name"] == "depict_chemical"
        revoked = restarted.post("/revoke", data={
            "client_id": credentials["client_id"], "client_secret": credentials["client_secret"],
            "token": access_token, "token_type_hint": "access_token",
        })
        assert revoked.status_code == 200
        assert restarted.post("/mcp", headers={"Authorization": f"Bearer {access_token}"}).status_code == 401
        assert restarted.get("/healthz").status_code in (200, 503)
