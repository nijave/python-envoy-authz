"""authlib store: clients, stateless codes, OP-internal tokens.

Ported from python-client-idp/app/store.py with one change: there is NO USERS
dict. Subjects are derived deterministically (federator.subject), so email and
name travel inside the stateless auth code and the OP-internal token record;
authenticate_user (in op/grants.py) reconstructs a User from them.
"""

import logging
import secrets
import threading
import time

from authlib.oauth2.rfc6749 import AuthorizationCodeMixin, ClientMixin, TokenMixin
from authlib.oidc.core import UserInfo
from itsdangerous import BadData, URLSafeTimedSerializer

from . import providers

logger = logging.getLogger(__name__)

DEFAULT_SCOPE = "openid profile email"

# OP-issued access/refresh tokens are STATELESS: signed, self-contained payloads
# (like the auth code below), not rows in a server-side table. This is what lets
# the OP run more than one replica — a token minted by one replica validates on
# any other, because validation is a signature+TTL check, not an in-memory
# lookup. (An opaque token in a per-process dict 401s the moment Vikunja's
# token→userinfo calls land on different replicas.) The signed timestamp bounds
# their lifetime; there is no server-side revocation (see the refresh grant).
ACCESS_TOKEN_TTL_SECONDS = 3600
_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600

# Bound once at startup (see configure), so no request path re-reads the
# environment or re-parses .env to sign or verify an auth code.
_signer: URLSafeTimedSerializer | None = None
_code_ttl_seconds: int = 10

# OP access/refresh token signers. Distinct salts (all bound to the same
# SECRET_KEY, which is shared across replicas) so no token type can be replayed
# as another — an access token is not a valid refresh token, code, etc.
_access_token_signer: URLSafeTimedSerializer | None = None
_op_refresh_signer: URLSafeTimedSerializer | None = None

# Refresh token for the native app's OAuth flow (federator.app_oauth). Signed
# with the same SECRET_KEY but a distinct salt so an auth code can never be
# replayed as a refresh token or vice versa. Stateless like the auth code, but
# long-lived; single use is not enforced because every use is additionally
# gated by the caller's mTLS certificate (the token grant refuses a refresh
# token whose subject does not match the presented certificate).
_app_refresh_signer: URLSafeTimedSerializer | None = None
_APP_REFRESH_TTL_SECONDS = 30 * 24 * 3600

# jti -> unix expiry, for single-use enforcement of the stateless auth codes
# (RFC 6749 4.1.2: a code MUST NOT be redeemed more than once). Bounded by the
# code TTL: entries are pruned on every access, so this holds at most the codes
# minted in the last `_code_ttl_seconds`.
_used_code_jtis: dict[str, float] = {}
_used_code_lock = threading.Lock()


def configure(secret_key: str, code_ttl_seconds: int) -> None:
    """Bind the auth-code + token signing keys and TTL. Called once at startup."""
    global _signer, _code_ttl_seconds, _app_refresh_signer
    global _access_token_signer, _op_refresh_signer
    _signer = URLSafeTimedSerializer(secret_key, salt="broker-auth-code")
    _app_refresh_signer = URLSafeTimedSerializer(secret_key, salt="app-refresh-token")
    _access_token_signer = URLSafeTimedSerializer(secret_key, salt="op-access-token")
    _op_refresh_signer = URLSafeTimedSerializer(secret_key, salt="op-refresh-token")
    _code_ttl_seconds = code_ttl_seconds
    with _used_code_lock:
        _used_code_jtis.clear()


def _code_signer() -> URLSafeTimedSerializer:
    if _signer is None:
        raise RuntimeError(
            "auth-code signer is not configured; call store.configure() at startup"
        )
    return _signer


def build_user_info(user, scope):
    """Construct a scoped UserInfo for `user` (sub, name, email).

    Claims with no value are OMITTED rather than emitted as null: OIDC Core
    5.3.2 says an absent claim SHOULD NOT be present with a null value, and
    `"email": null` is not something a downstream RP can provision a user from.
    """
    claims = {"sub": str(user.id)}
    if user.name:
        claims["name"] = user.name
    if user.email:
        claims["email"] = user.email
    return UserInfo(**claims).filter(scope)


class User:
    """A federated identity reconstructed from a stateless code or token."""

    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

    def get_user_id(self):
        return self.id


class OAuth2Client(ClientMixin):
    def __init__(
        self,
        client_id,
        client_secret,
        redirect_uris,
        scope=DEFAULT_SCOPE,
        grant_types=("authorization_code", "refresh_token"),
        response_types=("code",),
        token_endpoint_auth_method="client_secret_basic",
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uris = list(redirect_uris)
        self.scope = scope
        self.grant_types = list(grant_types)
        self.response_types = list(response_types)
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.client_metadata = {
            "client_id": client_id,
            "client_name": client_id,
            "redirect_uris": list(redirect_uris),
            "scope": scope,
            "grant_types": list(grant_types),
            "response_types": list(response_types),
            "token_endpoint_auth_method": token_endpoint_auth_method,
        }

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.redirect_uris[0] if self.redirect_uris else None

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope.split())
        return " ".join(s for s in scope.split() if s in allowed)

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret):
        # Compare BYTES: secrets.compare_digest raises TypeError on a str
        # containing non-ASCII (and on None), which would escape authlib's
        # OAuth2Error handling as a 500 instead of a 401 invalid_client.
        if not isinstance(client_secret, str) or not isinstance(
            self.client_secret, str
        ):
            return False
        return secrets.compare_digest(
            self.client_secret.encode("utf-8"), client_secret.encode("utf-8")
        )

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return method in ("client_secret_basic", "client_secret_post")
        return True

    def check_response_type(self, response_type):
        return response_type in self.response_types

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types


class OAuth2AuthorizationCode(AuthorizationCodeMixin):
    def __init__(
        self,
        code,
        client_id,
        redirect_uri,
        scope,
        user_id,
        email=None,
        name=None,
        nonce=None,
        code_challenge=None,
        code_challenge_method=None,
        auth_time=None,
    ):
        self.code = code
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.user_id = user_id
        self.email = email
        self.name = name
        self.nonce = nonce
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.auth_time = auth_time or int(time.time())

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_nonce(self):
        return self.nonce

    def get_auth_time(self):
        return self.auth_time

    def get_acr(self):
        return None

    def get_amr(self):
        return None


class OAuth2Token(TokenMixin):
    def __init__(self, client_id, user_id, email=None, name=None, **kwargs):
        self.client_id = client_id
        self.user_id = user_id
        self.email = email
        self.name = name
        self.access_token = kwargs.get("access_token")
        self.refresh_token = kwargs.get("refresh_token")
        self.token_type = kwargs.get("token_type", "Bearer")
        self.scope = kwargs.get("scope", "")
        self.expires_in = kwargs.get("expires_in", 3600)
        self.revoked = False
        self.issued_at = time.time()

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_expired(self):
        return time.time() > self.issued_at + self.expires_in

    def is_revoked(self):
        return self.revoked

    def get_user(self):
        return User(self.user_id, self.name, self.email) if self.user_id else None

    def get_client(self):
        return CLIENTS.get(self.client_id)

    def check_client(self, client):
        return self.client_id == client.client_id


CLIENTS = {}


def _reset():
    CLIENTS.clear()


def seed():
    if CLIENTS:
        return
    for provider in providers.PROVIDERS.values():
        CLIENTS[provider.client_id] = OAuth2Client(
            client_id=provider.client_id,
            client_secret=provider.client_secret,
            redirect_uris=[provider.redirect_url],
        )


def query_client(client_id):
    return CLIENTS.get(client_id)


def save_token(token, request):
    """No-op: OP access/refresh tokens are stateless (self-contained signed
    strings minted by create_access_token / create_op_refresh_token), so there
    is nothing to persist. Retained as authlib's AuthorizationServer.save_token
    hook. Making this a store write is what broke multi-replica: a token in one
    process's dict is invisible to the replica that later serves userinfo."""


def _access_signer_or_raise() -> URLSafeTimedSerializer:
    if _access_token_signer is None:
        raise RuntimeError(
            "access-token signer is not configured; call store.configure() at startup"
        )
    return _access_token_signer


def _op_refresh_signer_or_raise() -> URLSafeTimedSerializer:
    if _op_refresh_signer is None:
        raise RuntimeError(
            "op-refresh signer is not configured; call store.configure() at startup"
        )
    return _op_refresh_signer


def create_access_token(client, user, scope) -> str:
    """Mint a STATELESS OP access token: a signed payload carrying the client,
    subject and the user claims userinfo needs. Any replica can validate it with
    only the shared SECRET_KEY (see query_token) — no server-side token store."""
    user_id = user.get_user_id() if user else None
    return _access_signer_or_raise().dumps(
        {
            # Random so every minted token is a distinct string even when two are
            # issued in the same second with identical claims (the signed payload
            # is otherwise deterministic). Not tracked — statelessness means no
            # single-use enforcement (see create_op_refresh_token).
            "jti": secrets.token_urlsafe(8),
            "client_id": getattr(client, "client_id", client),
            "user_id": user_id,
            "email": getattr(user, "email", None),
            "name": getattr(user, "name", None),
            "scope": scope or "",
            "iat": int(time.time()),
        }
    )


def create_op_refresh_token(client, user, scope) -> str:
    """Mint a STATELESS OP refresh token (distinct salt from the access token).
    Stateless like the app-refresh token: bounded by its signed TTL, not
    single-use — a shared revocation store is exactly the per-replica state this
    fix removes."""
    user_id = user.get_user_id() if user else None
    return _op_refresh_signer_or_raise().dumps(
        {
            # Unique per mint (so rotation yields a distinct token); not tracked.
            "jti": secrets.token_urlsafe(8),
            "client_id": getattr(client, "client_id", client),
            "user_id": user_id,
            "email": getattr(user, "email", None),
            "name": getattr(user, "name", None),
            "scope": scope or "",
            "iat": int(time.time()),
        }
    )


def load_op_refresh_token(token, max_age=None):
    """Verify + decode an OP refresh token. Returns the payload dict, or None if
    the signature is invalid or the token is older than the refresh TTL."""
    if max_age is None:
        max_age = _REFRESH_TOKEN_TTL_SECONDS
    try:
        return _op_refresh_signer_or_raise().loads(token, max_age=max_age)
    except BadData:
        return None


def _token_record_from_payload(payload, access_token=None, refresh_token=None):
    record = OAuth2Token(
        client_id=payload["client_id"],
        user_id=payload["user_id"],
        email=payload.get("email"),
        name=payload.get("name"),
        access_token=access_token,
        refresh_token=refresh_token,
        scope=payload.get("scope", ""),
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
    )
    # Anchor is_expired() to when the token was actually issued, not now — load
    # already rejected anything past the signed TTL, this just keeps the window
    # from doubling.
    record.issued_at = payload.get("iat", record.issued_at)
    return record


def query_token(access_token):
    """Validate a bearer access token statelessly: verify its signature + TTL and
    reconstruct the token record from the signed payload. No dict lookup, so it
    resolves identically on every replica (the multi-replica userinfo fix)."""
    try:
        payload = _access_signer_or_raise().loads(
            access_token, max_age=ACCESS_TOKEN_TTL_SECONDS
        )
    except BadData:
        return None
    return _token_record_from_payload(payload, access_token=access_token)


def create_authorization_code(
    client_id,
    redirect_uri,
    scope,
    user_id,
    email=None,
    name=None,
    nonce=None,
    code_challenge=None,
    code_challenge_method=None,
):
    """Mint a STATELESS authorization code: a signed, self-contained token.

    email + name travel inside the signed payload so the OP can reconstruct the
    user at redemption without a USERS store. TTL is short (CODE_TTL_SECONDS).
    """
    return _code_signer().dumps(
        {
            "jti": secrets.token_urlsafe(8),
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "user_id": user_id,
            "email": email,
            "name": name,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "auth_time": int(time.time()),
        }
    )


def _consume_jti(jti: str, now: float, ttl: int) -> bool:
    """Record `jti` as redeemed; False if it was already redeemed.

    Enforces the single-use requirement for the stateless codes. Expired
    entries are pruned on each call, so the table holds at most one entry per
    code minted within the TTL window.
    """
    with _used_code_lock:
        for seen, expires_at in list(_used_code_jtis.items()):
            if expires_at <= now:
                del _used_code_jtis[seen]
        if jti in _used_code_jtis:
            return False
        _used_code_jtis[jti] = now + ttl
        return True


def load_authorization_code(code, max_age=None):
    """Verify, decode, and CONSUME a stateless authorization code.

    Returns the payload dict, or None if the signature is invalid, the code is
    older than `max_age` (defaults to the configured code TTL), or the code has
    already been redeemed. Redemption is single-use per RFC 6749 4.1.2 — the
    signature and TTL alone would let an observed code be replayed for the whole
    TTL window.
    """
    if max_age is None:
        max_age = _code_ttl_seconds
    try:
        payload = _code_signer().loads(code, max_age=max_age)
    except BadData:
        return None
    jti = payload.get("jti")
    if not jti:
        logger.warning("auth code has no jti; refusing (cannot enforce single use)")
        return None
    if not _consume_jti(jti, time.time(), max_age):
        logger.warning("auth code replay rejected (jti already redeemed)")
        return None
    return payload


def _app_refresh_signer_or_raise() -> URLSafeTimedSerializer:
    if _app_refresh_signer is None:
        raise RuntimeError(
            "app refresh signer is not configured; call store.configure() at startup"
        )
    return _app_refresh_signer


def create_app_refresh_token(user_id, email=None, name=None) -> str:
    """Mint a stateless refresh token for the native app's OAuth flow.

    Carries the federated subject so the token grant can re-federate without a
    server-side session store. The email/name travel inside so a re-mint after
    the access token expires keeps the same downstream user.
    """
    return _app_refresh_signer_or_raise().dumps(
        {"user_id": user_id, "email": email, "name": name, "iat": int(time.time())}
    )


def load_app_refresh_token(token, max_age=None):
    """Verify and decode an app refresh token. Returns the payload dict, or None
    if the signature is invalid or the token is older than the refresh TTL."""
    if max_age is None:
        max_age = _APP_REFRESH_TTL_SECONDS
    try:
        return _app_refresh_signer_or_raise().loads(token, max_age=max_age)
    except BadData:
        return None
