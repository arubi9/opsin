"""Single-owner OAuth, using the MCP SDK's protocol handlers.

The existing service key authenticates only the explicit browser consent step.
Access and refresh tokens are unrelated opaque values, persisted only as hashes.
The SDK's registered client credentials stay in the private database.
The caller must supply a dedicated private database directory and bound HTTP bodies.
"""
import base64
import binascii
import hashlib
import hmac
from html import escape
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from urllib.parse import unquote, urlencode, urlsplit

from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route, request_response

from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.handlers.register import RegistrationHandler
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.handlers.token import TokenErrorResponse, TokenHandler
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
    OAuthAuthorizationServerProvider, RefreshToken, RegistrationError, TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.routes import (
    _body_limited, _cors, build_metadata, cors_middleware, create_auth_routes,
    create_protected_resource_routes, validate_issuer_url,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

SCOPE = "opsin:depict"
_LIMIT = 128
_UNAPPROVED_TTL = 300
_SPENT_LIMIT = 4096
_PENDING_TTL = 300
_ACCESS_TTL = 3600
_REFRESH_TTL = 30 * 86400
_COOKIE = "__Host-opsin_oauth_csrf"
_CALLBACK = re.compile(
    # ChatGPT's documented callbacks: the shared platform redirect and the
    # per-connection segment (seen under both /connector/oauth and /assistant/oauth).
    r"https://chatgpt\.com/(?:connector_platform_oauth_redirect|(?:connector|assistant)/oauth/[A-Za-z0-9_-]{1,128})\Z")
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def _error(status: int = 400) -> Response:
    return JSONResponse({"error": "invalid_request"}, status_code=status, headers=_SECURITY_HEADERS)


async def _client_request(request: Request, *, revoke: bool = False) -> Request | Response:
    """Normalize SDK 1.30's form requirements, without authenticating clients."""
    try:
        form = await request.form()
    except (HTTPException, ValueError, UnicodeError):
        return _error()
    if (len(form.multi_items()) != len(form)
            or any(not isinstance(value, str) for _, value in form.multi_items())):
        return _error()
    fields = list(form.multi_items())
    authorization = request.headers.getlist("authorization")
    if len(authorization) > 1:
        return _error()
    if authorization:
        scheme, separator, encoded = authorization[0].partition(" ")
        if scheme.lower() != "basic" or not separator:
            return _error()
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
            client_id, secret = decoded.split(":", 1)
            if re.search(r"%(?![0-9A-Fa-f]{2})", client_id + secret):
                return _error()
            client_id = unquote(client_id, errors="strict")
            unquote(secret, errors="strict")
        except (ValueError, UnicodeError, binascii.Error):
            return _error()
        if not client_id or ("client_id" in form and form["client_id"] != client_id):
            return _error()
        if "client_id" not in form:
            fields.append(("client_id", client_id))
    if revoke and "client_secret" not in form:
        # SDK's revocation model requires even this optional credential. SDK
        # authentication still compares the actual Basic/body secret as usual.
        fields.append(("client_secret", ""))
    if fields == form.multi_items() and not authorization:
        return request  # Its parsed form is already cached.
    body = urlencode(fields).encode()
    headers = [(key, value) for key, value in request.scope["headers"]
               if key.lower() not in (b"content-type", b"content-length", b"authorization")]
    headers.extend([(b"content-type", b"application/x-www-form-urlencoded"),
                    (b"content-length", str(len(body)).encode())])
    if authorization:
        headers.append((b"authorization", ("Basic " + encoded).encode("ascii")))

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    # Guards and SDK handlers share this one reconstructed Request/cached form.
    return Request({**request.scope, "headers": headers}, receive)


class _Database(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class OpsinOAuth(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, api_key: str, issuer_url: str, db_path: Path):
        if not api_key:
            raise ValueError("OPSIN_API_KEY is required")
        issuer = AnyHttpUrl(issuer_url)
        validate_issuer_url(issuer)
        if issuer.username or issuer.password:
            raise ValueError("Issuer must not contain credentials")
        self.issuer_url = str(issuer).rstrip("/")
        self.resource_url = self.issuer_url + "/mcp"
        parsed = urlsplit(self.issuer_url)
        self._origin = f"{parsed.scheme}://{parsed.netloc}"
        self._api_key = api_key
        self._db_path = Path(db_path)
        parent = self._db_path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("OAuth database requires a dedicated owned directory with mode 0700")
        fd = os.open(self._db_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("OAuth database must be a private owned regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        connection = sqlite3.connect(self._db_path)
        try:
            connection.executescript("""
                PRAGMA auto_vacuum = FULL;
                CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, data TEXT NOT NULL, expires REAL);
                CREATE TABLE IF NOT EXISTS pending (
                    key TEXT PRIMARY KEY, expires REAL NOT NULL, data TEXT NOT NULL, csrf TEXT);
                CREATE TABLE IF NOT EXISTS codes (
                    key TEXT PRIMARY KEY, expires REAL NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens (
                    access_key TEXT PRIMARY KEY, refresh_key TEXT UNIQUE NOT NULL,
                    access_expires INTEGER NOT NULL, refresh_expires INTEGER NOT NULL,
                    family TEXT UNIQUE NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS spent_refresh (
                    key TEXT PRIMARY KEY, family TEXT NOT NULL, client_id TEXT NOT NULL,
                    expires INTEGER NOT NULL, resource TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS spent_family ON spent_refresh(family);
                CREATE TABLE IF NOT EXISTS rate (name TEXT PRIMARY KEY, bucket INTEGER NOT NULL, count INTEGER NOT NULL);
            """)
        finally:
            connection.close()

    def _db(self):
        # All read/modify/write operations, including consume-and-issue, serialize
        # across processes/instances. Exceptions roll back the entire exchange.
        # A native context manager also supports the SDK's frozen exceptions.
        connection = sqlite3.connect(self._db_path, timeout=5, factory=_Database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            now = time.time()
            connection.execute("DELETE FROM pending WHERE expires <= ?", (now,))
            connection.execute("DELETE FROM codes WHERE expires <= ?", (now,))
            connection.execute("DELETE FROM tokens WHERE refresh_expires <= ?", (now,))
            connection.execute("DELETE FROM spent_refresh WHERE expires <= ? OR family NOT IN (SELECT family FROM tokens)", (now,))
            connection.execute("DELETE FROM clients WHERE expires <= ?", (now,))
        except Exception:
            connection.close()
            raise
        return connection

    @staticmethod
    def _room(connection, table: str) -> bool:
        # Table names are internal constants, never supplied by a request.
        return connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] < _LIMIT

    @staticmethod
    def _rate(connection, name: str) -> bool:
        # Three fixed global buckets, not an unbounded per-IP cache. High-entropy
        # owner credentials plus one password attempt per transaction are required.
        bucket = int(time.time()) // 60
        connection.execute("""INSERT INTO rate VALUES (?, ?, 1) ON CONFLICT(name) DO UPDATE SET
            bucket=excluded.bucket, count=CASE WHEN rate.bucket=excluded.bucket THEN rate.count+1 ELSE 1 END""",
                           (name, bucket))
        return connection.execute("SELECT count FROM rate WHERE name=?", (name,)).fetchone()[0] <= _LIMIT

    def routes(self) -> list[Route]:
        registration = ClientRegistrationOptions(enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE])
        revocation = RevocationOptions(enabled=True)
        issuer = AnyHttpUrl(self.issuer_url)
        metadata = build_metadata(issuer, None, registration, revocation)
        metadata.token_endpoint_auth_methods_supported = ["none", "client_secret_post", "client_secret_basic"]
        metadata.revocation_endpoint_auth_methods_supported = metadata.token_endpoint_auth_methods_supported
        token_handler = TokenHandler(self, ClientAuthenticator(self))
        register_handler = RegistrationHandler(self, registration)
        authorize_handler = AuthorizationHandler(self)
        revoke_handler = RevocationHandler(self, ClientAuthenticator(self))

        async def register(request: Request) -> Response:
            # SDK RegistrationHandler doesn't catch malformed JSON. Also validate
            # raw redirect spelling before AnyUrl normalizes ports or dot segments.
            try:
                body = await request.json()
                # JSON permits escaped unpaired surrogates that the SDK's JSON
                # serializer cannot encode. Validate decoded keys/values first.
                json.dumps(body, ensure_ascii=False).encode("utf-8")
            except (ValueError, UnicodeError):
                return _error()
            if not isinstance(body, dict):
                return _error()
            if len(json.dumps(body)) > 8192:
                return JSONResponse({"error": "invalid_client_metadata"}, status_code=400, headers=_SECURITY_HEADERS)
            redirects = body.get("redirect_uris")
            if isinstance(redirects, list) and any(not isinstance(uri, str) or not _CALLBACK.fullmatch(uri) for uri in redirects):
                return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400, headers=_SECURITY_HEADERS)
            return await register_handler.handle(request)

        async def authorize(request: Request) -> Response:
            try:
                params = request.query_params if request.method == "GET" else await request.form()
            except (HTTPException, ValueError, UnicodeError):
                return _error()
            if len(params.getlist("resource")) > 1 or len(params.getlist("redirect_uri")) > 1:
                return _error()
            return await authorize_handler.handle(request)

        async def token(request: Request) -> Response:
            normalized = await _client_request(request)
            if isinstance(normalized, Response):
                return normalized
            request = normalized
            form = await request.form()
            # TokenHandler currently ignores TokenRequest.resource. Inspect the
            # cached form, then pass this SAME Request to its SDK handler.
            if any(value != self.resource_url for value in form.getlist("resource")):
                return token_handler.response(TokenErrorResponse(error="invalid_request"))
            if any(value != SCOPE for value in form.getlist("scope")):
                return token_handler.response(TokenErrorResponse(error="invalid_scope"))
            verifier = form.get("code_verifier", "")
            if form.get("grant_type") == "authorization_code" and (
                    not isinstance(verifier, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier)):
                return token_handler.response(TokenErrorResponse(error="invalid_request"))
            return await token_handler.handle(request)

        async def revoke(request: Request) -> Response:
            normalized = await _client_request(request, revoke=True)
            if isinstance(normalized, Response):
                return normalized
            return await revoke_handler.handle(normalized)

        routes = create_auth_routes(self, issuer, client_registration_options=registration, revocation_options=revocation)
        replacements = {
            "/.well-known/oauth-authorization-server": cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"]),
            "/register": _cors(_body_limited(request_response(register)), ["POST", "OPTIONS"]),
            "/authorize": _body_limited(request_response(authorize)),
            "/token": _cors(_body_limited(request_response(token)), ["POST", "OPTIONS"]),
            "/revoke": _cors(_body_limited(request_response(revoke)), ["POST", "OPTIONS"]),
        }
        # Reuse SDK CORS/body-limit wrappers, including CORS on 413 responses.
        routes = [Route(route.path, replacements[route.path], methods=route.methods)
                  if route.path in replacements else route for route in routes]
        routes.append(Route("/oauth/consent", self._consent, methods=["GET", "POST"]))
        routes.extend(create_protected_resource_routes(AnyHttpUrl(self.resource_url), [issuer], scopes_supported=[SCOPE]))
        return routes

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._db() as connection:
            row = connection.execute("SELECT data FROM clients WHERE id=?", (client_id,)).fetchone()
        return OAuthClientInformationFull.model_validate_json(row["data"]) if row else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        redirects = client_info.redirect_uris or []
        if not 1 <= len(redirects) <= 3 or any(not _CALLBACK.fullmatch(str(uri)) for uri in redirects):
            raise RegistrationError("invalid_redirect_uri", "Only ChatGPT HTTPS callbacks are supported")
        if (client_info.token_endpoint_auth_method not in ("none", "client_secret_post", "client_secret_basic")
                or client_info.scope != SCOPE or set(client_info.grant_types) != {"authorization_code", "refresh_token"}
                or client_info.response_types != ["code"] or client_info.jwks_uri or client_info.jwks
                or len(client_info.client_name or "") > 200 or len(client_info.model_dump_json()) > 8192):
            raise RegistrationError("invalid_client_metadata", "Unsupported client metadata")
        with self._db() as connection:
            if not self._rate(connection, "register") or not self._room(connection, "clients"):
                raise RegistrationError("invalid_client_metadata", "Client registration capacity reached")
            connection.execute("INSERT INTO clients VALUES (?, ?, ?)",
                               (client_info.client_id, client_info.model_dump_json(), time.time() + _UNAPPROVED_TTL))

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if (params.resource not in (None, self.resource_url) or (params.scopes is not None and params.scopes != [SCOPE])
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge)
                or len(params.state or "") > 1024 or params.redirect_uri not in (client.redirect_uris or [])):
            raise AuthorizeError("invalid_request", "Invalid authorization parameters")
        transaction = secrets.token_urlsafe(32)
        params = params.model_copy(update={"resource": self.resource_url, "scopes": [SCOPE]})
        data = {"client_id": client.client_id, "params": params.model_dump(mode="json")}
        with self._db() as connection:
            if not self._rate(connection, "authorize") or not self._room(connection, "pending"):
                raise AuthorizeError("temporarily_unavailable", "Authorization capacity reached")
            connection.execute("INSERT INTO pending VALUES (?, ?, ?, NULL)",
                               (_hash(transaction), time.time() + _PENDING_TTL, json.dumps(data)))
        return self.issuer_url + "/oauth/consent?transaction=" + transaction

    async def _consent(self, request: Request) -> Response:
        if request.method == "POST":
            if (request.headers.get("origin") not in (None, self._origin)
                    or request.headers.get("sec-fetch-site") == "cross-site"):
                return _error(403)
            try:
                fields = await request.form()
            except (HTTPException, ValueError, UnicodeError):
                return _error()
        else:
            fields = request.query_params
        transaction = fields.get("transaction", "")
        if not isinstance(transaction, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", transaction):
            return _error()
        with self._db() as connection:
            row = connection.execute("SELECT * FROM pending WHERE key=?", (_hash(transaction),)).fetchone()
            if not row:
                return _error()
            data = json.loads(row["data"])
            params = AuthorizationParams.model_validate(data["params"])
            client_row = connection.execute("SELECT data FROM clients WHERE id=?", (data["client_id"],)).fetchone()
            client = OAuthClientInformationFull.model_validate_json(client_row["data"]) if client_row else None
            if not client or params.resource != self.resource_url or params.redirect_uri not in (client.redirect_uris or []):
                return _error()
            if request.method == "GET":
                csrf = secrets.token_urlsafe(32)
                connection.execute("UPDATE pending SET csrf=? WHERE key=?", (_hash(csrf), _hash(transaction)))
                response = HTMLResponse(f"""<!doctype html><html><head><title>OPSIN consent</title></head><body>
                    <h1>Connect OPSIN</h1><p>Unverified client: {escape(client.client_name or 'Unnamed client')}</p>
                    <p>Callback: {escape(str(params.redirect_uri))}</p><p>Permission: {SCOPE} (chemical depictions)</p>
                    <form method="post" action="/oauth/consent">
                    <input type="hidden" name="transaction" value="{transaction}">
                    <input type="hidden" name="csrf" value="{csrf}">
                    <label>Owner service key <input type="password" name="api_key" autocomplete="current-password" required></label>
                    <button name="decision" value="approve">Approve</button>
                    <button name="decision" value="deny" formnovalidate>Deny</button>
                    </form></body></html>""", headers=_SECURITY_HEADERS)
                response.set_cookie(_COOKIE, csrf, max_age=_PENDING_TTL, secure=True, httponly=True, samesite="lax", path="/")
                return response
            # Consume the transaction even for an incorrect key/CSRF. There is no
            # reusable password-guessing endpoint and no authenticated GET session.
            connection.execute("DELETE FROM pending WHERE key=?", (_hash(transaction),))
            csrf = fields.get("csrf", "")
            cookie = request.cookies.get(_COOKIE, "")
            if (not isinstance(csrf, str) or not csrf or not cookie or not row["csrf"]
                    or not _equal(csrf, cookie) or not _equal(_hash(csrf), row["csrf"])):
                return _error(403)
            if not self._rate(connection, "consent"):
                return _error(429)
            decision = fields.get("decision")
            if decision == "deny":
                redirect = construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state)
            elif decision == "approve":
                key = fields.get("api_key", "")
                if not isinstance(key, str) or not _equal(key, self._api_key):
                    return _error(403)
                if not self._room(connection, "codes"):
                    return _error(503)
                code = AuthorizationCode(code=secrets.token_urlsafe(32), client_id=data["client_id"],
                                         expires_at=time.time() + _PENDING_TTL, subject="owner", **params.model_dump(exclude={"state"}))
                connection.execute("INSERT INTO codes VALUES (?, ?, ?)",
                                   (_hash(code.code), code.expires_at, code.model_dump_json(exclude={"code"})))
                # Only authenticated, explicit approval makes registration durable.
                connection.execute("UPDATE clients SET expires=NULL WHERE id=?", (client.client_id,))
                redirect = construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state)
            else:
                return _error()
        response = RedirectResponse(redirect, status_code=302, headers=_SECURITY_HEADERS)
        response.delete_cookie(_COOKIE, secure=True, httponly=True, samesite="lax", path="/")
        return response

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        with self._db() as connection:
            row = connection.execute("SELECT data FROM codes WHERE key=?", (_hash(authorization_code),)).fetchone()
        if row:
            code = AuthorizationCode(code=authorization_code, **json.loads(row["data"]))
            if code.client_id == client.client_id and code.resource == self.resource_url and code.scopes == [SCOPE]:
                return code
        return None

    @staticmethod
    def _drop_family(connection, family: str) -> None:
        connection.execute("DELETE FROM tokens WHERE family=?", (family,))
        connection.execute("DELETE FROM spent_refresh WHERE family=?", (family,))

    def _replay(self, connection, client_id: str | None, key: str) -> None:
        # Called only after SDK client authentication (or its provider contract).
        # Unknown tokens and tokens belonging to another client revoke nothing.
        row = connection.execute("SELECT family FROM spent_refresh WHERE key=? AND client_id=? AND resource=?",
                                 (key, client_id, self.resource_url)).fetchone()
        if row:
            self._drop_family(connection, row["family"])

    def _issue(self, connection, client_id: str, scopes: list[str], family: str | None = None) -> OAuthToken:
        if not self._room(connection, "tokens"):
            raise TokenError("invalid_request", "Token capacity reached")
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = int(time.time())
        data = json.dumps({"client_id": client_id, "scopes": scopes, "resource": self.resource_url, "subject": "owner"})
        connection.execute("INSERT INTO tokens VALUES (?, ?, ?, ?, ?, ?)",
                           (_hash(access), _hash(refresh), now + _ACCESS_TTL, now + _REFRESH_TTL,
                            family or secrets.token_urlsafe(32), data))
        return OAuthToken(access_token=access, refresh_token=refresh, expires_in=_ACCESS_TTL, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        with self._db() as connection:
            key = _hash(authorization_code.code)
            row = connection.execute("SELECT data FROM codes WHERE key=?", (key,)).fetchone()
            if not row:
                raise TokenError("invalid_grant", "Code is expired or already used")
            stored = AuthorizationCode(code=authorization_code.code, **json.loads(row["data"]))
            if (stored.expires_at <= time.time() or stored.client_id != client.client_id
                    or stored.resource != self.resource_url or stored.scopes != [SCOPE] or stored != authorization_code):
                raise TokenError("invalid_grant", "Code binding mismatch")
            if connection.execute("DELETE FROM codes WHERE key=?", (key,)).rowcount != 1:
                raise TokenError("invalid_grant", "Code already used")
            return self._issue(connection, stored.client_id, stored.scopes)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        with self._db() as connection:
            key = _hash(refresh_token)
            row = connection.execute("SELECT * FROM tokens WHERE refresh_key=?", (key,)).fetchone()
            if not row:
                self._replay(connection, client.client_id, key)
        # Returning None after the transaction commits lets the SDK report
        # invalid_grant without rolling back a detected family's revocation.
        if row:
            data = json.loads(row["data"])
            if data["client_id"] == client.client_id and data["resource"] == self.resource_url and data["scopes"] == [SCOPE]:
                return RefreshToken(token=refresh_token, expires_at=row["refresh_expires"], **data)
        return None

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        with self._db() as connection:
            key = _hash(refresh_token.token)
            row = connection.execute("SELECT * FROM tokens WHERE refresh_key=?", (key,)).fetchone()
            if not row:
                # Covers a stale object loaded before a concurrent rotation.
                self._replay(connection, client.client_id, key)
            else:
                stored = RefreshToken(token=refresh_token.token, expires_at=row["refresh_expires"], **json.loads(row["data"]))
                if (not stored.expires_at or stored.expires_at <= time.time() or stored.client_id != client.client_id
                        or stored.resource != self.resource_url or stored != refresh_token):
                    raise TokenError("invalid_grant", "Refresh token binding mismatch")
                if scopes != [SCOPE] or stored.scopes != [SCOPE]:
                    raise TokenError("invalid_scope", "Unsupported scope")
                if connection.execute("SELECT count(*) FROM spent_refresh").fetchone()[0] >= _SPENT_LIMIT:
                    # Never evict live reuse evidence while leaving its grant
                    # active. At the hard history cap, require fresh consent.
                    self._drop_family(connection, row["family"])
                else:
                    if connection.execute("DELETE FROM tokens WHERE refresh_key=?", (key,)).rowcount != 1:
                        raise TokenError("invalid_grant", "Refresh token already used")
                    connection.execute("INSERT INTO spent_refresh VALUES (?, ?, ?, ?, ?)",
                                       (key, row["family"], stored.client_id, stored.expires_at, stored.resource))
                    return self._issue(connection, stored.client_id, scopes, row["family"])
        # IMPORTANT: revocation above must COMMIT before raising invalid_grant.
        raise TokenError("invalid_grant", "Refresh token is expired or already used")

    async def load_access_token(self, token: str) -> AccessToken | None:
        with self._db() as connection:
            row = connection.execute("SELECT * FROM tokens WHERE access_key=?", (_hash(token),)).fetchone()
        if row:
            data = json.loads(row["data"])
            if data["resource"] == self.resource_url and data["scopes"] == [SCOPE]:
                # Keep expired access keys loadable for SDK pair revocation while
                # their refresh token is alive. verify_token checks access expiry.
                return AccessToken(token=token, expires_at=row["access_expires"], claims={"iss": self.issuer_url}, **data)
        return None

    async def verify_token(self, token: str) -> AccessToken | None:
        if _equal(token, self._api_key):
            return None
        access = await self.load_access_token(token)
        return access if access and access.expires_at and access.expires_at > time.time() else None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        with self._db() as connection:
            row = connection.execute("SELECT family FROM tokens WHERE (access_key=? OR refresh_key=?) AND json_extract(data, '$.client_id')=?",
                                     (_hash(token.token), _hash(token.token), token.client_id)).fetchone()
            if row:
                self._drop_family(connection, row["family"])
