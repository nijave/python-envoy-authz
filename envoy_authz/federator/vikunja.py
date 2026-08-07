"""HTTP client for the Vikunja API (cold paths only: refresh + federate).

Per the design spec, GET /api/v1/user is NOT called on the hot path; session
validity is decided locally via exp + refresh/federation. So this client has no
validate_bearer helper. The refresh-token cookie is a Set-Cookie response
header (not a JSON field); it is extracted verbatim, including the
comma-bearing Expires case ported from the source broker. Federation mints an
OP auth code and POSTs {code, redirect_url}; Vikunja exchanges the code at the
OP itself. Bearer tokens and refresh cookies are never logged.
"""

import logging
from http.cookies import SimpleCookie

import httpx
from pydantic import BaseModel

from .providers import Provider
from .subject import Subject

logger = logging.getLogger(__name__)

_REFRESH_PATH = "/api/v1/user/token/refresh"
_REFRESH_COOKIE_NAME = "vikunja_refresh_token"


def callback_path(provider: Provider) -> str:
    """The Vikunja backend path that redeems a federation auth code.

    Shared with the browser-bootstrap path (grpc_service.Check): that path must
    let a request to this exact path through untouched rather than treat it as
    a plain federated request, or Vikunja's own callback exchange never runs.
    """
    return f"/api/v1/auth/openid/{provider.provider_key}/callback"


class DownstreamError(Exception):
    """Vikunja returned an error or was unreachable.

    `retryable` drives the Check deny status: Vikunja was unreachable or
    returned 5xx — Check denies with HTTP 503 so clients can retry. Terminal
    failures (4xx, including a 401 on refresh, which means the session was
    revoked/expired) deny with HTTP 401, and on refresh specifically the
    ladder falls through to federation instead of denying.
    """

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
    ):
        super().__init__(message)
        self.retryable = retryable


class VikunjaSession(BaseModel):
    bearer: str  # Vikunja JWT; plain str (injected as a header)
    refresh_cookie: str | None  # rotated vikunja_refresh_token value
    exp: float  # bearer exp (unix), decoded from the payload
    user_id: str | None  # `id` claim from the payload, for logging


class VikunjaClient:
    """Wraps httpx calls to Vikunja. The caller owns the httpx client."""

    def __init__(self, provider: Provider, client: httpx.Client):
        self._provider = provider
        self._client = client

    @property
    def session_secret(self) -> str | None:
        """Vikunja's `service.secret` (HS256), or None when not configured.

        Exposed so the decision ladder does not have to reach into
        `_provider.extra` for a backend-specific key name.
        """
        return self._provider.extra.get("session_secret") or None

    # --- refresh ---------------------------------------------------------

    def refresh(self, refresh_cookie: str) -> VikunjaSession:
        """POST /api/v1/user/token/refresh with the Cookie header; return the
        rotated session. Raises DownstreamError on 401 (session revoked/
        expired; the ladder falls through to federation instead of denying).
        Raises DownstreamError(retryable=True) on transport error / 5xx (Check
        denies 503). Raises DownstreamError on a terminal 4xx (Check denies
        401)."""
        try:
            resp = self._client.post(
                _REFRESH_PATH,
                headers={"Cookie": f"{_REFRESH_COOKIE_NAME}={refresh_cookie}"},
            )
        except httpx.HTTPError as exc:
            logger.warning("Vikunja refresh transport error")
            raise DownstreamError("refresh transport error", retryable=True) from exc
        if resp.status_code == 401:
            logger.info("Vikunja refresh rejected (revoked/expired)")
            raise DownstreamError("refresh rejected")
        if resp.status_code != 200:
            logger.warning("Vikunja refresh failed (status=%d)", resp.status_code)
            raise DownstreamError(
                f"refresh status {resp.status_code}",
                retryable=resp.status_code >= 500,
            )
        return self._session_from_response(resp)

    # --- federation ------------------------------------------------------

    def federate(self, subject: Subject) -> VikunjaSession:
        """Mint a stateless OP auth code, POST {code, redirect_url} to Vikunja's
        openid callback, return the resulting session. Vikunja exchanges the
        code at the OP /oauth/token itself. Raises DownstreamError on failure."""
        from .store import create_authorization_code

        if not subject.email:
            # Vikunja provisions users by email; without one the callback fails
            # with an opaque 4xx. Fail here so the log names the actual cause.
            logger.warning(
                "cannot federate sub=%s: client cert has no rfc822Name SAN",
                subject.sub,
            )
            raise DownstreamError(
                "client certificate has no email (rfc822Name SAN); "
                "cannot provision a downstream user"
            )

        code = create_authorization_code(
            client_id=self._provider.client_id,
            redirect_uri=self._provider.redirect_url,
            scope=self._provider.scope,
            user_id=subject.sub,
            email=subject.email,
            name=subject.name,
            nonce=None,
        )
        callback = callback_path(self._provider)
        try:
            resp = self._client.post(
                callback,
                json={"code": code, "redirect_url": self._provider.redirect_url},
            )
        except httpx.HTTPError as exc:
            logger.warning("Vikunja openid callback transport error")
            raise DownstreamError("callback transport error", retryable=True) from exc
        if resp.status_code != 200:
            logger.warning(
                "Vikunja openid callback failed (status=%d)", resp.status_code
            )
            raise DownstreamError(
                f"callback status {resp.status_code}",
                retryable=resp.status_code >= 500,
            )
        return self._session_from_response(resp)

    # --- shared response parsing ----------------------------------------

    def _session_from_response(self, resp: httpx.Response) -> VikunjaSession:
        try:
            body = resp.json()
        except ValueError as exc:
            logger.warning("Vikunja returned non-JSON body")
            raise DownstreamError("non-JSON body") from exc
        bearer = body.get("token")
        if not bearer:
            logger.warning("Vikunja response missing token")
            raise DownstreamError("missing token")
        # The rotated refresh cookie comes from Set-Cookie, not the JSON body.
        refresh_cookie = _extract_refresh_cookie(resp)
        if refresh_cookie is None:
            logger.warning("Vikunja response missing Set-Cookie refresh token")
        exp, user_id = _decode_bearer_payload(bearer)
        return VikunjaSession(
            bearer=bearer,
            refresh_cookie=refresh_cookie,
            exp=exp,
            user_id=user_id,
        )


def _extract_refresh_cookie(resp: httpx.Response) -> str | None:
    """Extract the vikunja_refresh_token value from a Set-Cookie header,
    handling the comma-bearing Expires case. httpx exposes raw Set-Cookie
    headers via resp.headers.get_list('set-cookie') so a comma inside one
    cookie's Expires does not split across headers."""
    for raw in resp.headers.get_list("set-cookie"):
        # SimpleCookie parses one Set-Cookie at a time; a trailing Expires comma
        # is contained within the single raw string.
        jar = SimpleCookie()
        jar.load(raw)
        morsel = jar.get(_REFRESH_COOKIE_NAME)
        if morsel is not None and morsel.value:
            return morsel.value
    return None


def _decode_bearer_payload(bearer: str) -> tuple[float, str | None]:
    """Decode exp + id from our own obtained bearer's payload. No signature
    check (spec lines 437-443): we trust the token we received over our trusted
    channel to Vikunja. Returns (exp_unix, user_id).

    A token we cannot decode, or one carrying no usable `exp`, is a broken
    downstream contract and raises. Defaulting it to exp=0.0 and caching it
    anyway would silently make every subsequent request re-hit Vikunja (the cache
    entry can never look fresh), quietly defeating the never-call-Vikunja-on-the-
    hot-path invariant with no log to diagnose it by.
    """
    import jwt as pyjwt

    try:
        # decode without verification — we only read exp/id off our own token
        payload = pyjwt.decode(bearer, options={"verify_signature": False})
    except Exception as exc:
        logger.warning("Vikunja bearer is not a decodable JWT")
        raise DownstreamError("undecodable bearer") from exc
    exp = float(payload.get("exp") or 0.0)
    if exp <= 0.0:
        logger.warning("Vikunja bearer carries no usable exp claim")
        raise DownstreamError("bearer has no exp")
    user_id = str(payload["id"]) if "id" in payload else None
    return exp, user_id
