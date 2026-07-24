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

# OP-issued refresh tokens are pruned on this schedule. The access-token records
# in TOKENS carry their own expires_in and are pruned via is_expired().
_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600

# Bound once at startup (see configure), so no request path re-reads the
# environment or re-parses .env to sign or verify an auth code.
_signer: URLSafeTimedSerializer | None = None
_code_ttl_seconds: int = 10

# jti -> unix expiry, for single-use enforcement of the stateless auth codes
# (RFC 6749 4.1.2: a code MUST NOT be redeemed more than once). Bounded by the
# code TTL: entries are pruned on every access, so this holds at most the codes
# minted in the last `_code_ttl_seconds`.
_used_code_jtis: dict[str, float] = {}
_used_code_lock = threading.Lock()


def configure(secret_key: str, code_ttl_seconds: int) -> None:
    """Bind the auth-code signing key + TTL. Called once at startup."""
    global _signer, _code_ttl_seconds
    _signer = URLSafeTimedSerializer(secret_key, salt="broker-auth-code")
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
TOKENS = {}
REFRESH_TOKENS = {}


def _reset():
    CLIENTS.clear()
    TOKENS.clear()
    REFRESH_TOKENS.clear()


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


def _prune_tokens(now: float) -> None:
    """Drop expired records so TOKENS/REFRESH_TOKENS cannot grow unboundedly.

    Without this every federation permanently leaked two dict entries (each
    holding the user's email/name) for the life of the process.
    """
    for access_token, record in list(TOKENS.items()):
        if record.is_expired():
            del TOKENS[access_token]
    for refresh_token, record in list(REFRESH_TOKENS.items()):
        if now > record.issued_at + _REFRESH_TOKEN_TTL_SECONDS:
            del REFRESH_TOKENS[refresh_token]


def save_token(token, request):
    user = request.user
    user_id = user.get_user_id() if user else None
    record = OAuth2Token(
        client_id=request.client.client_id,
        user_id=user_id,
        email=getattr(user, "email", None),
        name=getattr(user, "name", None),
        **token,
    )
    _prune_tokens(time.time())
    TOKENS[record.access_token] = record
    if record.refresh_token:
        REFRESH_TOKENS[record.refresh_token] = record
    return record


def query_token(access_token):
    return TOKENS.get(access_token)


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
