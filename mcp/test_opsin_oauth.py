"""Local HTTP security tests; no external OAuth service or running server."""
import asyncio
import base64
import hashlib
import importlib
import json
from html.parser import HTMLParser
import sqlite3
import stat
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.applications import Starlette

ISSUER = "https://opsin.example"
RESOURCE = ISSUER + "/mcp"
CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"
KEY = "owner-service-key-" + "a" * 48
SCOPE = "opsin:depict"
VERIFIER = "a" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


class Inputs(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.values = {}
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("type") == "hidden":
            self.values[attrs["name"]] = attrs.get("value", "")


@pytest.fixture
async def env(tmp_path):
    module = importlib.import_module("opsin_oauth")
    db = tmp_path / "private" / "oauth.sqlite"
    provider = module.OpsinOAuth(KEY, ISSUER, db)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=Starlette(routes=provider.routes())),
                                 base_url=ISSUER, follow_redirects=False) as client:
        yield provider, client, db


async def register(client, **overrides):
    body = {"redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none", "scope": SCOPE,
            "client_name": "ChatGPT"}
    body.update(overrides)
    return await client.post("/register", json=body)


async def registered(client, **overrides):
    response = await register(client, **overrides)
    assert response.status_code == 201, response.text
    return response.json()


def authorize_params(client, **overrides):
    params = {"client_id": client["client_id"], "response_type": "code", "redirect_uri": CALLBACK,
              "scope": SCOPE, "state": "opaque-client-state", "code_challenge": CHALLENGE,
              "code_challenge_method": "S256", "resource": RESOURCE}
    params.update(overrides)
    return params


async def consent_page(http, client, **overrides):
    response = await http.get("/authorize", params=authorize_params(client, **overrides))
    assert response.status_code == 302, response.text
    assert urlsplit(response.headers["location"]).path == "/oauth/consent"
    page = await http.get(response.headers["location"])
    assert page.status_code == 200, page.text
    return page, Inputs(page.text).values


async def approved_code(http, client, **overrides):
    _, fields = await consent_page(http, client, **overrides)
    response = await http.post("/oauth/consent", data={**fields, "api_key": KEY, "decision": "approve"},
                               headers={"Origin": ISSUER})
    assert response.status_code == 302, response.text
    location = urlsplit(response.headers["location"])
    assert location.scheme + "://" + location.netloc + location.path == CALLBACK
    query = parse_qs(location.query)
    assert query["state"] == ["opaque-client-state"]
    return query["code"][0]


def code_form(client, authorization_code, **overrides):
    fields = {"grant_type": "authorization_code", "client_id": client["client_id"], "code": authorization_code,
              "redirect_uri": CALLBACK, "code_verifier": VERIFIER, "resource": RESOURCE}
    if client.get("client_secret"):
        fields["client_secret"] = client["client_secret"]
    fields.update(overrides)
    return fields


async def issued(http, client):
    code = await approved_code(http, client)
    response = await http.post("/token", data=code_form(client, code))
    assert response.status_code == 200, response.text
    return response.json()


def refresh_form(client, tokens, **overrides):
    fields = {"grant_type": "refresh_token", "client_id": client["client_id"],
              "refresh_token": tokens["refresh_token"], "resource": RESOURCE}
    if client.get("client_secret"):
        fields["client_secret"] = client["client_secret"]
    fields.update(overrides)
    return fields


def oauth_error(response):
    if response.status_code == 302:
        return parse_qs(urlsplit(response.headers["location"]).query).get("error", [None])[0]
    assert response.status_code in (400, 401, 403, 429, 503), response.text
    return response.json().get("error")


async def test_discovery_registration_and_no_api_key_token(env):
    provider, http, _ = env
    assert provider.resource_url == RESOURCE
    discovery = (await http.get("/.well-known/oauth-authorization-server")).json()
    assert discovery["authorization_endpoint"] == ISSUER + "/authorize"
    assert discovery["token_endpoint"] == ISSUER + "/token"
    assert discovery["registration_endpoint"] == ISSUER + "/register"
    assert discovery["revocation_endpoint"] == ISSUER + "/revoke"
    assert set(discovery["token_endpoint_auth_methods_supported"]) == {
        "none", "client_secret_post", "client_secret_basic"}
    assert discovery["scopes_supported"] == [SCOPE]
    assert discovery["code_challenge_methods_supported"] == ["S256"]
    metadata = (await http.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert metadata["resource"] == RESOURCE
    assert metadata["authorization_servers"] == [ISSUER + "/"]
    assert metadata["scopes_supported"] == [SCOPE]
    client = await registered(http)
    assert client["scope"] == SCOPE and not client.get("client_secret")
    assert await provider.verify_token(KEY) is None
    assert await provider.verify_token("unknown") is None
    response = await http.post("/token", data={"grant_type": "client_credentials", "client_id": client["client_id"]})
    assert response.status_code == 400


@pytest.mark.parametrize("redirect", [
    "http://chatgpt.com/connector_platform_oauth_redirect",
    "https://evil.example/connector_platform_oauth_redirect",
    "https://chatgpt.com.evil.example/connector_platform_oauth_redirect",
    "https://user@chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com:8443/connector_platform_oauth_redirect",
    "https://chatgpt.com:443/connector_platform_oauth_redirect",
    CALLBACK + "?next=evil", CALLBACK + "#fragment", CALLBACK + "/",
    "https://chatgpt.com/connector/oauth/", "https://chatgpt.com/connector/oauth/a/b",
    "https://chatgpt.com/connector/oauth/%2f", "https://chatgpt.com/connector/oauth/..",
    "https://chatgpt.com/assistant/oauth/", "https://chatgpt.com/assistant/oauth/a/b",
    "https://chatgpt.com/assistant/oauth/x/", "https://chatgpt.com/assistant/oauth/%2f",
])
async def test_registration_redirect_allowlist(env, redirect):
    _, http, _ = env
    assert oauth_error(await register(http, redirect_uris=[redirect])) == "invalid_redirect_uri"


@pytest.mark.parametrize("overrides", [
    {"token_endpoint_auth_method": "private_key_jwt"}, {"scope": "admin"},
    {"response_types": ["code", "token"]}, {"grant_types": ["authorization_code", "refresh_token", "password"]},
    {"redirect_uris": [CALLBACK] * 5}, {"client_name": "x" * 10000},
    {"jwks_uri": "http://127.0.0.1:9000/private"},
])
async def test_registration_metadata_restrictions(env, overrides):
    _, http, _ = env
    assert oauth_error(await register(http, **overrides)) in ("invalid_client_metadata", "invalid_redirect_uri")


@pytest.mark.parametrize("redirect", [
    "https://chatgpt.com/connector/oauth/callback_123-ABC",
    "https://chatgpt.com/assistant/oauth/27WYzWDApyq9",
])
async def test_safe_callback_segment_and_client_metadata_urls_never_fetched(env, redirect):
    _, http, _ = env
    result = await registered(http, redirect_uris=[redirect],
                              client_uri="http://127.0.0.1:9000/never-fetched")
    assert result["client_id"]


@pytest.mark.parametrize("overrides,error", [
    ({"resource": "https://other.example/mcp"}, "invalid_request"),
    ({"scope": "admin"}, "invalid_scope"), ({"redirect_uri": "https://evil.example/callback"}, "invalid_request"),
    ({"code_challenge_method": "plain"}, "invalid_request"),
    ({"code_challenge": ""}, "invalid_request"), ({"code_challenge": "short"}, "invalid_request"),
    ({"response_type": "token"}, "unsupported_response_type"), ({"client_id": "unknown"}, "invalid_request"),
])
async def test_authorize_security_matrix(env, overrides, error):
    _, http, _ = env
    client = await registered(http)
    assert oauth_error(await http.get("/authorize", params=authorize_params(client, **overrides))) == error


async def test_consent_get_security_headers_escaping_no_code_or_secret(env):
    _, http, db = env
    client = await registered(http, client_name='<script>alert("untrusted")</script>')
    page, fields = await consent_page(http, client)
    assert "<script>" not in page.text and "&lt;script&gt;" in page.text
    assert KEY not in page.text
    assert 'type="password"' in page.text
    assert 'value="approve"' in page.text and 'value="deny"' in page.text
    assert "no-store" in page.headers["cache-control"]
    assert page.headers["referrer-policy"] == "no-referrer"
    assert "form-action 'self'" in page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    cookie = page.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert fields["csrf"] and fields["transaction"]
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM codes").fetchone()[0] == 0
    # Query-string credentials cannot approve, even with a valid transaction.
    response = await http.get("/oauth/consent", params={**fields, "api_key": KEY, "decision": "approve"})
    assert KEY not in response.text
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM codes").fetchone()[0] == 0


@pytest.mark.parametrize("attack", ["missing_cookie", "wrong_cookie", "missing_csrf", "wrong_csrf", "wrong_key",
                                   "cross_origin", "null_origin", "fetch_cross_site", "no_decision", "deny"])
async def test_consent_protection_matrix(env, attack, caplog):
    _, http, db = env
    client = await registered(http)
    page, fields = await consent_page(http, client)
    data = {**fields, "api_key": KEY, "decision": "approve"}
    headers = {"Origin": ISSUER}
    if attack == "missing_cookie":
        http.cookies.clear()
    if attack == "wrong_cookie":
        http.cookies.clear()
        http.cookies.set("__Host-opsin_oauth_csrf", "wrong")
    if attack == "missing_csrf":
        data.pop("csrf")
    if attack == "wrong_csrf":
        data["csrf"] = "wrong"
    if attack == "wrong_key":
        data["api_key"] = "incorrect-secret-never-reflect"
    if attack == "cross_origin":
        headers["Origin"] = "https://evil.example"
    if attack == "null_origin":
        headers["Origin"] = "null"
    if attack == "fetch_cross_site":
        headers["Sec-Fetch-Site"] = "cross-site"
    if attack == "no_decision":
        data.pop("decision")
    if attack == "deny":
        data["decision"] = "deny"
    response = await http.post("/oauth/consent", data=data, headers=headers)
    if attack == "deny":
        assert oauth_error(response) == "access_denied"
    else:
        assert response.status_code in (400, 403)
    assert KEY not in response.text + str(response.headers) + caplog.text
    assert "incorrect-secret-never-reflect" not in response.text + caplog.text
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM codes").fetchone()[0] == 0


async def test_consent_one_time_and_wrong_key_cannot_retry(env):
    _, http, _ = env
    client = await registered(http)
    _, fields = await consent_page(http, client)
    data = {**fields, "api_key": "wrong", "decision": "approve"}
    assert (await http.post("/oauth/consent", data=data)).status_code == 403
    data["api_key"] = KEY
    assert (await http.post("/oauth/consent", data=data)).status_code == 400
    _, fields = await consent_page(http, client)
    data = {**fields, "api_key": KEY, "decision": "approve"}
    assert (await http.post("/oauth/consent", data=data)).status_code == 302
    assert (await http.post("/oauth/consent", data=data)).status_code == 400


@pytest.mark.parametrize("overrides,error", [
    ({"code_verifier": "b" * 64}, "invalid_grant"), ({"code": "unknown"}, "invalid_grant"),
    ({"resource": "https://other.example/mcp"}, "invalid_request"),
    ({"redirect_uri": "https://evil.example/"}, "invalid_request"),
])
async def test_token_exchange_security_matrix(env, overrides, error):
    provider, http, _ = env
    client = await registered(http)
    code = await approved_code(http, client)
    response = await http.post("/token", data=code_form(client, code, **overrides))
    assert oauth_error(response) == error
    response = await http.post("/token", data=code_form(client, code))
    assert response.status_code == 200, response.text
    tokens = response.json()
    verified = await provider.verify_token(tokens["access_token"])
    assert verified.client_id == client["client_id"] and verified.resource == RESOURCE
    assert verified.scopes == [SCOPE] and verified.subject == "owner"
    assert oauth_error(await http.post("/token", data=code_form(client, code))) == "invalid_grant"


@pytest.mark.parametrize("method", ["none", "client_secret_post", "client_secret_basic"])
async def test_client_authentication_binding_and_success(env, method):
    provider, http, _ = env
    client = await registered(http, token_endpoint_auth_method=method)
    other = await registered(http)
    code = await approved_code(http, client)
    assert oauth_error(await http.post("/token", data=code_form(other, code))) == "invalid_grant"
    data = code_form(client, code)
    headers = {}
    if method == "client_secret_basic":
        data.pop("client_secret")
        wrong = base64.b64encode(f'{client["client_id"]}:wrong'.encode()).decode()
        assert (await http.post("/token", data=data, headers={"Authorization": "Basic " + wrong})).status_code == 401
        credential = base64.b64encode(f'{client["client_id"]}:{client["client_secret"]}'.encode()).decode()
        headers["Authorization"] = "Basic " + credential
    elif method == "client_secret_post":
        assert (await http.post("/token", data={**data, "client_secret": "wrong"})).status_code == 401
    response = await http.post("/token", data=data, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["expires_in"] == 3600
    assert response.json()["scope"] == SCOPE
    assert await provider.verify_token(response.json()["access_token"])
    assert "no-store" in response.headers["cache-control"]


async def test_resource_omission_and_duplicate_wrong_resource(env):
    _, http, _ = env
    client = await registered(http)
    params = authorize_params(client)
    params.pop("resource")
    response = await http.get("/authorize", params=params)
    page = await http.get(response.headers["location"])
    fields = Inputs(page.text).values
    response = await http.post("/oauth/consent", data={**fields, "api_key": KEY, "decision": "approve"})
    code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
    data = code_form(client, code)
    response = await http.post("/token", content=str(httpx.QueryParams(list(data.items()) + [("resource", "https://evil.example")])),
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert oauth_error(response) == "invalid_request"
    data.pop("resource")
    response = await http.post("/token", data=data)
    assert response.status_code == 200, response.text
    data = refresh_form(client, response.json())
    data.pop("resource")
    assert (await http.post("/token", data=data)).status_code == 200


async def test_refresh_scope_client_resource_rotation_and_revoke(env):
    provider, http, _ = env
    client = await registered(http)
    other = await registered(http)
    old = await issued(http, client)
    assert oauth_error(await http.post("/token", data=refresh_form(other, old))) == "invalid_grant"
    assert oauth_error(await http.post("/token", data=refresh_form(client, old, scope="admin"))) == "invalid_scope"
    assert oauth_error(await http.post("/token", data=refresh_form(client, old, resource="https://evil.example"))) == "invalid_request"
    response = await http.post("/token", data=refresh_form(client, old))
    assert response.status_code == 200, response.text
    new = response.json()
    assert new["access_token"] != old["access_token"] and new["refresh_token"] != old["refresh_token"]
    assert await provider.verify_token(old["access_token"]) is None
    # Replay revokes the successor (covered separately); test explicit revocation
    # here without first invalidating the grant by replaying its spent refresh.
    # A different registered client cannot revoke another client's pair.
    data = {"client_id": other["client_id"], "client_secret": "", "token": new["access_token"]}
    assert (await http.post("/revoke", data=data)).status_code == 200
    assert await provider.verify_token(new["access_token"])
    data.update(client_id=client["client_id"])
    assert (await http.post("/revoke", data=data)).status_code == 200
    assert await provider.verify_token(new["access_token"]) is None
    assert oauth_error(await http.post("/token", data=refresh_form(client, new))) == "invalid_grant"
    another = await issued(http, client)
    data["token"] = another["refresh_token"]
    assert (await http.post("/revoke", data=data)).status_code == 200
    assert await provider.verify_token(another["access_token"]) is None


async def test_persistence_hashing_permissions_and_wrong_audience(env):
    provider, http, db = env
    client = await registered(http)
    tokens = await issued(http, client)
    code = await approved_code(http, client)
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
    dump = db.read_bytes()
    for secret in (KEY, tokens["access_token"], tokens["refresh_token"], code):
        assert secret.encode() not in dump
    reloaded = type(provider)(KEY, ISSUER, db)
    assert await reloaded.verify_token(tokens["access_token"])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=Starlette(routes=reloaded.routes())), base_url=ISSUER) as second:
        assert (await second.post("/token", data=code_form(client, code))).status_code == 200
        refreshed = await second.post("/token", data=refresh_form(client, tokens))
        assert refreshed.status_code == 200
        live = refreshed.json()["access_token"]
    assert await reloaded.verify_token(live)
    wrong = type(provider)(KEY, "https://other.example", db)
    with sqlite3.connect(db) as connection:
        row = connection.execute("SELECT data FROM tokens LIMIT 1").fetchone()
        assert json.loads(row[0])["resource"] == RESOURCE
    assert await wrong.verify_token(live) is None


async def test_expiry_cleanup(env, monkeypatch):
    provider, http, db = env
    client = await registered(http)
    tokens = await issued(http, client)
    code = await approved_code(http, client)
    _, fields = await consent_page(http, client)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 301)
    assert (await http.post("/oauth/consent", data={**fields, "api_key": KEY, "decision": "approve"})).status_code == 400
    assert oauth_error(await http.post("/token", data=code_form(client, code))) == "invalid_grant"
    monkeypatch.setattr(time, "time", lambda: now + 3601)
    assert await provider.verify_token(tokens["access_token"]) is None
    # Refresh is still valid after the access token expires.
    assert (await http.post("/token", data=refresh_form(client, tokens))).status_code == 200
    monkeypatch.setattr(time, "time", lambda: now + 32 * 86400)
    assert oauth_error(await http.post("/token", data=refresh_form(client, tokens))) == "invalid_grant"
    with sqlite3.connect(db) as connection:
        for table in ("pending", "codes", "tokens"):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


async def test_atomic_stale_code_and_refresh_exchanges_across_instances(env):
    provider, http, db = env
    other = type(provider)(KEY, ISSUER, db)
    client = await registered(http)
    info = await provider.get_client(client["client_id"])
    code = await approved_code(http, client)
    loaded = await provider.load_authorization_code(info, code)
    stale = await other.load_authorization_code(info, code)
    results = await asyncio.gather(provider.exchange_authorization_code(info, loaded),
                                   other.exchange_authorization_code(info, stale), return_exceptions=True)
    successes = [item for item in results if not isinstance(item, BaseException)]
    assert len(successes) == 1
    token = successes[0]
    first = await provider.load_refresh_token(info, token.refresh_token)
    stale = await other.load_refresh_token(info, token.refresh_token)
    results = await asyncio.gather(provider.exchange_refresh_token(info, first, [SCOPE]),
                                   other.exchange_refresh_token(info, stale, [SCOPE]), return_exceptions=True)
    assert sum(not isinstance(item, BaseException) for item in results) == 1
    assert await provider.verify_token(token.access_token) is None


async def test_bounded_clients_pending_and_rate(env, monkeypatch):
    _, http, db = env
    now = time.time()
    client = await registered(http)
    # Approved clients outlive the short unapproved TTL used by the pending test below.
    await approved_code(http, client)
    for number in range(127):
        assert (await register(http)).status_code == 201
    assert (await register(http)).status_code in (400, 429)
    monkeypatch.setattr(time, "time", lambda: now + 61)
    assert (await register(http)).status_code == 400  # persistent client cap, not just rate limit
    for number in range(128):
        assert (await http.get("/authorize", params=authorize_params(client))).status_code == 302
    response = await http.get("/authorize", params=authorize_params(client))
    assert oauth_error(response) == "temporarily_unavailable"
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM clients").fetchone()[0] == 128
        assert connection.execute("SELECT count(*) FROM pending").fetchone()[0] == 128
    monkeypatch.setattr(time, "time", lambda: now + 400)
    assert (await http.get("/authorize", params=authorize_params(client))).status_code == 302
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM pending").fetchone()[0] == 1


async def test_sdk_cors_and_body_limits(env):
    _, http, _ = env
    for path in ("/register", "/token", "/revoke"):
        preflight = await http.options(path, headers={"Origin": "https://chatgpt.com", "Access-Control-Request-Method": "POST"})
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == "*"
        response = await http.post(path, content=b"x" * (4 * 1024 * 1024 + 1), headers={"Origin": "https://chatgpt.com"})
        assert response.status_code == 413
        assert response.headers["access-control-allow-origin"] == "*"


def test_no_chmod_existing_shared_parent(tmp_path):
    module = importlib.import_module("opsin_oauth")
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    before = stat.S_IMODE(shared.stat().st_mode)
    with pytest.raises(ValueError, match="0700|private|dedicated"):
        module.OpsinOAuth(KEY, ISSUER, shared / "oauth.sqlite")
    assert stat.S_IMODE(shared.stat().st_mode) == before


@pytest.mark.parametrize("body", [b"{", b"null", b"[]", b"\xff", b"{" + b'"nested":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}"])
async def test_malformed_registration_json_is_controlled_4xx(env, body):
    _, http, _ = env
    response = await http.post("/register", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 400


@pytest.mark.parametrize("path", ["/authorize", "/token", "/revoke", "/oauth/consent"])
async def test_malformed_multipart_is_controlled_4xx(env, path):
    _, http, _ = env
    response = await http.post(path, content=b"malformed", headers={"Content-Type": "multipart/form-data"})
    assert response.status_code in (400, 401, 403)


async def test_pkce_verifier_rfc_length_is_required(env):
    _, http, _ = env
    client = await registered(http)
    weak = "x"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(weak.encode()).digest()).decode().rstrip("=")
    code = await approved_code(http, client, code_challenge=challenge)
    response = await http.post("/token", data=code_form(client, code, code_verifier=weak))
    assert oauth_error(response) == "invalid_request"


async def test_default_scopes_and_implicit_redirect(env):
    provider, http, _ = env
    client = await registered(http)
    params = authorize_params(client)
    params.pop("scope")
    params.pop("redirect_uri")
    response = await http.get("/authorize", params=params)
    page = await http.get(response.headers["location"])
    response = await http.post("/oauth/consent", data={**Inputs(page.text).values, "api_key": KEY, "decision": "approve"})
    code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
    form = code_form(client, code)
    form.pop("redirect_uri")
    response = await http.post("/token", data=form)
    assert response.status_code == 200, response.text
    assert (await provider.verify_token(response.json()["access_token"])).scopes == [SCOPE]


async def test_bounded_codes_and_pairs_capacity_rollback(env, monkeypatch):
    provider, http, db = env
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    client = await registered(http)
    codes = [await approved_code(http, client) for _ in range(128)]
    monkeypatch.setattr(time, "time", lambda: now + 61)
    _, fields = await consent_page(http, client)
    response = await http.post("/oauth/consent", data={**fields, "api_key": KEY, "decision": "approve"})
    assert response.status_code == 503
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM codes").fetchone()[0] == 128
    tokens = []
    for code in codes:
        response = await http.post("/token", data=code_form(client, code))
        assert response.status_code == 200, response.text
        tokens.append(response.json())
    # Rotation replaces a pair, so it must still work at the capacity ceiling.
    response = await http.post("/token", data=refresh_form(client, tokens[0]))
    assert response.status_code == 200, response.text
    tokens[0] = response.json()
    code = await approved_code(http, client)
    assert oauth_error(await http.post("/token", data=code_form(client, code))) == "invalid_request"
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM tokens").fetchone()[0] == 128
        assert connection.execute("SELECT count(*) FROM codes").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM rate").fetchone()[0] <= 3
    await provider.revoke_token(await provider.verify_token(tokens[0]["access_token"]))
    assert (await http.post("/token", data=code_form(client, code))).status_code == 200


async def test_expired_access_token_can_revoke_still_live_refresh_pair(env, monkeypatch):
    provider, http, _ = env
    client = await registered(http)
    tokens = await issued(http, client)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 3601)
    assert await provider.verify_token(tokens["access_token"]) is None
    response = await http.post("/revoke", data={"client_id": client["client_id"], "client_secret": "", "token": tokens["access_token"]})
    assert response.status_code == 200
    assert oauth_error(await http.post("/token", data=refresh_form(client, tokens))) == "invalid_grant"


async def test_csrf_and_transaction_are_hashed_at_rest(env):
    _, http, db = env
    client = await registered(http)
    _, fields = await consent_page(http, client)
    assert fields["csrf"].encode() not in db.read_bytes()
    assert fields["transaction"].encode() not in db.read_bytes()


async def test_public_client_standard_revocation_without_secret(env):
    provider, http, _ = env
    client = await registered(http)
    tokens = await issued(http, client)
    response = await http.post("/revoke", data={"client_id": client["client_id"], "token": tokens["access_token"]})
    assert response.status_code == 200, response.text
    assert await provider.verify_token(tokens["access_token"]) is None
    assert oauth_error(await http.post("/token", data=refresh_form(client, tokens))) == "invalid_grant"


async def test_audit_anonymous_registration_expires_only_owner_approval_persists(env, monkeypatch):
    provider, http, db = env
    approved = await registered(http)
    await approved_code(http, approved)  # Approval, even before token exchange, counts.
    active = await registered(http)
    tokens = await issued(http, active)
    previewed = await registered(http)
    await consent_page(http, previewed)  # Merely visiting authorize/consent does not count.
    denied = await registered(http)
    _, fields = await consent_page(http, denied)
    await http.post("/oauth/consent", data={**fields, "decision": "deny"})
    rejected = await registered(http)
    _, fields = await consent_page(http, rejected)
    await http.post("/oauth/consent", data={**fields, "decision": "approve", "api_key": "wrong"})
    for _ in range(123):
        await registered(http)
    assert (await register(http)).status_code == 400
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 2 * 86400)
    reloaded = type(provider)(KEY, ISSUER, db)
    assert await reloaded.get_client(approved["client_id"])
    assert await reloaded.get_client(active["client_id"])
    for client in (previewed, denied, rejected):
        assert await reloaded.get_client(client["client_id"]) is None
    assert (await register(http)).status_code == 201
    assert (await http.post("/token", data=refresh_form(active, tokens))).status_code == 200
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM clients").fetchone()[0] == 3


async def test_audit_approved_clients_are_never_anonymously_evicted(env, monkeypatch):
    provider, http, db = env
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    clients = []
    for _ in range(128):
        client = await registered(http)
        await approved_code(http, client)
        clients.append(client)
    monkeypatch.setattr(time, "time", lambda: now + 2 * 86400)
    reloaded = type(provider)(KEY, ISSUER, db)
    assert (await register(http)).status_code == 400
    for client in clients:
        assert await reloaded.get_client(client["client_id"])


@pytest.mark.parametrize("method", ["none", "client_secret_post"])
async def test_audit_refresh_replay_revokes_only_authenticated_clients_family(env, method):
    provider, http, db = env
    client = await registered(http, token_endpoint_auth_method=method)
    other = await registered(http)
    old = await issued(http, client)
    unrelated = await issued(http, client)
    response = await http.post("/token", data=refresh_form(client, old))
    assert response.status_code == 200
    successor = response.json()
    reloaded = type(provider)(KEY, ISSUER, db)
    assert await reloaded.verify_token(successor["access_token"])
    assert oauth_error(await http.post("/token", data=refresh_form(other, old))) == "invalid_grant"
    assert oauth_error(await http.post("/token", data=refresh_form(client, {"refresh_token": "random-unknown"}))) == "invalid_grant"
    if method == "client_secret_post":
        assert (await http.post("/token", data=refresh_form(client, old, client_secret="wrong"))).status_code == 401
    assert await reloaded.verify_token(successor["access_token"])
    assert oauth_error(await http.post("/token", data=refresh_form(client, old))) == "invalid_grant"
    assert await reloaded.verify_token(successor["access_token"]) is None
    assert oauth_error(await http.post("/token", data=refresh_form(client, successor))) == "invalid_grant"
    assert await reloaded.verify_token(unrelated["access_token"])
    assert (await http.post("/token", data=refresh_form(client, unrelated))).status_code == 200


async def test_audit_stale_refresh_exchange_commits_family_revocation(env):
    provider, http, db = env
    other = type(provider)(KEY, ISSUER, db)
    client = await registered(http)
    info = await provider.get_client(client["client_id"])
    tokens = await issued(http, client)
    loaded = await provider.load_refresh_token(info, tokens["refresh_token"])
    stale = await other.load_refresh_token(info, tokens["refresh_token"])
    successor = await provider.exchange_refresh_token(info, loaded, [SCOPE])
    from mcp.server.auth.provider import TokenError
    with pytest.raises(TokenError, match="invalid_grant"):
        await other.exchange_refresh_token(info, stale, [SCOPE])
    reloaded = type(provider)(KEY, ISSUER, db)
    assert await reloaded.verify_token(successor.access_token) is None
    assert await reloaded.load_refresh_token(info, successor.refresh_token) is None


async def test_audit_expired_spent_refresh_does_not_revoke_successor(env, monkeypatch):
    _, http, _ = env
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    client = await registered(http)
    old = await issued(http, client)
    monkeypatch.setattr(time, "time", lambda: now + 2 * 86400)
    response = await http.post("/token", data=refresh_form(client, old))
    assert response.status_code == 200
    successor = response.json()
    monkeypatch.setattr(time, "time", lambda: now + 30 * 86400 + 2)
    assert oauth_error(await http.post("/token", data=refresh_form(client, old))) == "invalid_grant"
    assert (await http.post("/token", data=refresh_form(client, successor))).status_code == 200


async def test_audit_refresh_history_bound_fails_closed_and_commits(env, monkeypatch):
    provider, http, db = env
    module = importlib.import_module("opsin_oauth")
    monkeypatch.setattr(module, "_SPENT_LIMIT", 2)
    client = await registered(http)
    current = await issued(http, client)
    unrelated = await issued(http, client)
    for _ in range(2):
        response = await http.post("/token", data=refresh_form(client, current))
        assert response.status_code == 200
        current = response.json()
    assert oauth_error(await http.post("/token", data=refresh_form(client, current))) == "invalid_grant"
    reloaded = type(provider)(KEY, ISSUER, db)
    assert await reloaded.verify_token(current["access_token"]) is None
    assert await reloaded.verify_token(unrelated["access_token"])
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM spent_refresh").fetchone()[0] <= 2


def basic_header(client, secret=None):
    credential = f'{client["client_id"]}:{secret if secret is not None else client["client_secret"]}'
    return "Basic " + base64.b64encode(credential.encode()).decode()


async def test_audit_basic_only_header_code_refresh_and_revocation(env):
    provider, http, _ = env
    client = await registered(http, token_endpoint_auth_method="client_secret_basic")
    code = await approved_code(http, client)
    headers = {"Authorization": basic_header(client)}
    form = code_form(client, code)
    form.pop("client_id")
    form.pop("client_secret")
    response = await http.post("/token", data=form, headers=headers)
    assert response.status_code == 200, response.text
    first = response.json()
    form = refresh_form(client, first)
    form.pop("client_id")
    form.pop("client_secret")
    response = await http.post("/token", data=form, headers=headers)
    assert response.status_code == 200, response.text
    tokens = response.json()
    response = await http.post("/revoke", data={"token": tokens["access_token"]}, headers=headers)
    assert response.status_code == 200, response.text
    assert await provider.verify_token(tokens["access_token"]) is None


@pytest.mark.parametrize("path", ["/token", "/revoke"])
@pytest.mark.parametrize("attack", ["mismatch", "duplicate_id", "duplicate_authorization", "bad_base64",
                                   "no_colon", "invalid_utf8", "empty_id", "bad_percent"])
async def test_audit_basic_malformed_mismatched_and_duplicate_credentials(env, path, attack, caplog):
    provider, http, _ = env
    client = await registered(http, token_endpoint_auth_method="client_secret_basic")
    code = await approved_code(http, client)
    form = code_form(client, code)
    form.pop("client_secret")
    header = basic_header(client)
    if path == "/revoke":
        response = await http.post("/token", data=form, headers={"Authorization": header})
        assert response.status_code == 200
        token = response.json()["access_token"]
        form = {"token": token, "client_id": client["client_id"]}
    fields = list(form.items())
    headers = [("Authorization", header), ("Content-Type", "application/x-www-form-urlencoded")]
    if attack == "mismatch":
        fields = [(key, "different-client" if key == "client_id" else value) for key, value in fields]
    elif attack == "duplicate_id":
        fields.append(("client_id", client["client_id"]))
    elif attack == "duplicate_authorization":
        headers.append(("Authorization", header))
    elif attack == "bad_base64":
        headers[0] = ("Authorization", "Basic !invalid!")
    else:
        decoded = {"no_colon": "missing-colon", "invalid_utf8": None, "empty_id": ":secret",
                   "bad_percent": "bad%xx:secret"}[attack]
        raw = b"\xff:secret" if decoded is None else decoded.encode()
        headers[0] = ("Authorization", "Basic " + base64.b64encode(raw).decode())
    response = await http.post(path, content=str(httpx.QueryParams(fields)), headers=headers)
    assert response.status_code in (400, 401), response.text
    assert client["client_secret"] not in response.text + caplog.text
    if path == "/revoke":
        assert await provider.verify_token(token)


@pytest.mark.parametrize("field", ["client_name", "contacts", "software_id", "software_version"])
async def test_audit_registration_rejects_unpaired_surrogates(env, field, caplog):
    _, http, db = env
    value = KEY + "\ud800"
    payload = {"redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none",
               field: [value] if field == "contacts" else value}
    response = await http.post("/register", content=json.dumps(payload).encode(),
                               headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert KEY not in response.text + caplog.text
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM clients").fetchone()[0] == 0


async def test_audit_registration_flood_recovers_after_short_unapproved_ttl(env, monkeypatch):
    _, http, _ = env
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    for _ in range(128):
        assert (await register(http)).status_code == 201
    assert (await register(http)).status_code == 400
    monkeypatch.setattr(time, "time", lambda: now + 301)
    assert (await register(http)).status_code == 201
