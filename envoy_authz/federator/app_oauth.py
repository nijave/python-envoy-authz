"""OAuth2 authorization-code + PKCE flow for the native app, served entirely by
the federator so the client never sees the downstream Vikunja OIDC handshake.

The Vikunja Flutter app performs a standard authorization-code + PKCE login:

    GET  /oauth/authorize?response_type=code&client_id=vikunja-flutter
           &redirect_uri=vikunja-flutter://callback&code_challenge=...
           &code_challenge_method=S256&state=...
    POST /api/v1/oauth/token  (grant_type=authorization_code, code, code_verifier,
                               client_id, redirect_uri)

It expects a redirect to `vikunja-flutter://callback?code=...&state=...`, then a
`{access_token, refresh_token, expires_in}` JSON body; and it refreshes with
`grant_type=refresh_token` at the same token endpoint. None of these endpoints
exist on Vikunja for this client — Vikunja mints federation codes
server-to-server only (see op/routes.py). This module lets the federator
synthesize both legs from the mTLS identity via Envoy `denied_response`s, doing
the whole Vikunja OIDC federation server-side. The app only ever sees its own
code and tokens; it never observes the `/auth/openid/broker` bootstrap the
browser flow uses.

Security model: the transport is mutually-authenticated TLS, so the real
principal on BOTH legs is the client certificate (Check has already verified
it). The authorization code is bound to that subject (`user_id=subject.sub`) and
the token leg is refused unless the SAME certificate subject redeems it — which
for this transport is stronger than PKCE alone. PKCE is still verified against
the app's own S256 challenge when present. The refresh token is likewise bound
to the certificate subject.
"""

import base64
import hashlib
import logging
import re
import secrets
import time
from urllib.parse import urlencode

from .store import (
    DEFAULT_SCOPE,
    create_app_refresh_token,
    create_authorization_code,
    load_app_refresh_token,
    load_authorization_code,
)
from .subject import Subject

logger = logging.getLogger(__name__)

# Fixed by the app (lib/core/oauth/oauth_service.dart). This is a front-channel
# client OF the federator, distinct from the downstream provider clients in
# providers.yaml (which are the federator acting as a client of Vikunja).
APP_CLIENT_ID = "vikunja-flutter"
APP_REDIRECT_URIS = frozenset({"vikunja-flutter://callback"})

AUTHORIZE_PATH = "/oauth/authorize"
TOKEN_PATH_SUFFIX = "/oauth/token"

# RFC 7636 4.1/4.2: verifier and challenge are 43-128 chars of the unreserved
# set. Enforced on both legs so nothing outside it ever reaches the ascii
# encode / compare_digest below (either would raise on arbitrary input).
_PKCE_VALUE = re.compile(r"[A-Za-z0-9._~-]{43,128}")


class AppOAuthError(Exception):
    """An invalid app OAuth request. `error` is an OAuth2 error code (RFC 6749
    5.2); `status` is the HTTP status the federator denies with."""

    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status


def _one(value):
    """Collapse a parse_qs value (always a list) to its first element. Accepts a
    plain str too, so callers can pass either a parsed query or a plain dict."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def is_app_authorize(path_no_query: str, query: dict[str, list[str]]) -> bool:
    """True for the app's `GET /oauth/authorize` (matched by client_id so a
    browser navigation to the same path still falls through to the bootstrap)."""
    return (
        path_no_query == AUTHORIZE_PATH
        and _one(query.get("client_id")) == APP_CLIENT_ID
    )


def is_app_token(path_no_query: str, form: dict[str, list[str]]) -> bool:
    """True for the app's token request. Matched by client_id in the form body,
    so only the app's own POST is intercepted."""
    return (
        path_no_query.endswith(TOKEN_PATH_SUFFIX)
        and _one(form.get("client_id")) == APP_CLIENT_ID
    )


def build_authorize_location(query: dict[str, list[str]], subject: Subject) -> str:
    """Validate the authorize request, mint a subject-bound PKCE code, and
    return the `vikunja-flutter://callback?code=...&state=...` URL to 302 to.

    Raises AppOAuthError on any invalid parameter."""
    response_type = _one(query.get("response_type"))
    redirect_uri = _one(query.get("redirect_uri"))
    code_challenge = _one(query.get("code_challenge"))
    method = _one(query.get("code_challenge_method")) or "plain"
    state = _one(query.get("state"))

    if response_type != "code":
        raise AppOAuthError("unsupported_response_type", "only response_type=code")
    if redirect_uri not in APP_REDIRECT_URIS:
        raise AppOAuthError("invalid_request", "redirect_uri is not allowed")
    if not code_challenge or method != "S256":
        raise AppOAuthError("invalid_request", "an S256 code_challenge is required")
    if not isinstance(code_challenge, str) or not _PKCE_VALUE.fullmatch(code_challenge):
        raise AppOAuthError("invalid_request", "code_challenge is malformed")
    if not subject.email:
        # Vikunja provisions users by email; without one the downstream
        # federation would fail with an opaque 4xx. Fail here, named.
        raise AppOAuthError(
            "access_denied",
            "client certificate has no email (rfc822Name SAN)",
            status=401,
        )

    code = create_authorization_code(
        client_id=APP_CLIENT_ID,
        redirect_uri=redirect_uri,
        scope=DEFAULT_SCOPE,
        user_id=subject.sub,
        email=subject.email,
        name=subject.name,
        code_challenge=code_challenge,
        code_challenge_method=method,
    )
    params = {"code": code}
    if state is not None:
        params["state"] = state
    return f"{redirect_uri}?{urlencode(params)}"


def _verify_pkce(verifier, challenge: str) -> bool:
    """RFC 7636 S256: base64url(sha256(verifier)) == challenge, no padding."""
    if not isinstance(verifier, str) or not _PKCE_VALUE.fullmatch(verifier):
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, challenge)


def handle_token(
    form: dict[str, list[str]], subject: Subject, mint_session
) -> dict[str, object]:
    """Dispatch the app's token request to the matching grant and return the
    token response body dict. `mint_session(subject)` returns an object with
    `.bearer` (str) and `.exp` (unix float) — the freshly federated Vikunja
    session. Raises AppOAuthError on an invalid request; a DownstreamError from
    `mint_session` propagates to the caller."""
    grant_type = _one(form.get("grant_type"))
    if grant_type == "authorization_code":
        return _authorization_code_grant(form, subject, mint_session)
    if grant_type == "refresh_token":
        return _refresh_token_grant(form, subject, mint_session)
    raise AppOAuthError(
        "unsupported_grant_type", f"unsupported grant_type {grant_type!r}"
    )


def _token_response(session, subject: Subject) -> dict[str, object]:
    expires_in = max(1, int(session.exp - time.time()))
    refresh_token = create_app_refresh_token(
        user_id=subject.sub, email=subject.email, name=subject.name
    )
    return {
        "access_token": session.bearer,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": refresh_token,
    }


def _authorization_code_grant(
    form: dict[str, list[str]], subject: Subject, mint_session
) -> dict[str, object]:
    code = _one(form.get("code"))
    code_verifier = _one(form.get("code_verifier"))
    redirect_uri = _one(form.get("redirect_uri"))
    if not code or not isinstance(code, str):
        # A JSON body can carry any type; a non-str would raise inside the
        # signer rather than fail verification.
        raise AppOAuthError("invalid_request", "missing or malformed code")

    payload = load_authorization_code(code)
    if payload is None:
        raise AppOAuthError("invalid_grant", "code invalid, expired, or already used")
    if payload.get("client_id") != APP_CLIENT_ID:
        raise AppOAuthError("invalid_grant", "code was not issued to this client")
    if payload.get("redirect_uri") != redirect_uri:
        raise AppOAuthError("invalid_grant", "redirect_uri mismatch")
    if str(payload.get("user_id")) != str(subject.sub):
        # The code is bound to the certificate that requested it.
        raise AppOAuthError(
            "invalid_grant", "code was issued to a different certificate", status=401
        )
    challenge = payload.get("code_challenge")
    if challenge and not _verify_pkce(code_verifier, challenge):
        raise AppOAuthError("invalid_grant", "PKCE verification failed")

    session = mint_session(subject)
    logger.info("app-token-issued sub=%s grant=authorization_code", subject.sub)
    return _token_response(session, subject)


def _refresh_token_grant(
    form: dict[str, list[str]], subject: Subject, mint_session
) -> dict[str, object]:
    token = _one(form.get("refresh_token"))
    if not token or not isinstance(token, str):
        # A JSON body can carry any type; a non-str would raise inside the
        # signer rather than fail verification.
        raise AppOAuthError("invalid_request", "missing or malformed refresh_token")
    payload = load_app_refresh_token(token)
    if payload is None:
        raise AppOAuthError("invalid_grant", "refresh_token invalid or expired")
    if str(payload.get("user_id")) != str(subject.sub):
        raise AppOAuthError(
            "invalid_grant",
            "refresh_token was issued to a different certificate",
            status=401,
        )

    session = mint_session(subject)
    logger.info("app-token-issued sub=%s grant=refresh_token", subject.sub)
    return _token_response(session, subject)
