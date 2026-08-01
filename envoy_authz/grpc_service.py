import logging
import urllib.parse

import grpc
from cryptography import x509
from envoy.config.core.v3.base_pb2 import HeaderValue, HeaderValueOption
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2, status_pb2
from grpc_health.v1 import health, health_pb2_grpc
from opentelemetry import trace

from envoy_authz.identity import parse_client_identity

from .config import Config, verify_client_cert
from .federator.providers import PROVIDERS, get_provider, provider_for_host
from .federator.session import SessionCache, get_bearer
from .federator.subject import derive_subject
from .federator.vikunja import DownstreamError, VikunjaClient

logger = logging.getLogger(__name__)

FRIGATE_HOST = "frigate.apps.somemissing.info"

# Headers never emitted to logs (they may carry a bearer / refresh cookie).
_SENSITIVE_HEADERS = frozenset(("authorization", "proxy-authorization", "cookie"))

# Federation is OPT-IN (see config.Settings.federation): when it is not
# configured the lifespan never calls init_federator, these stay None, and Check
# behaves exactly as it did before federation existed — mTLS allow gate plus the
# Frigate proxy secret. That is a deliberate, logged configuration state, not a
# fallback for a half-wired federator.
_vikunja: VikunjaClient | None = None
_SESSIONS: SessionCache | None = None

# The nested federation callback (us -> Vikunja -> back into our own /oauth/token
# for the code exchange, JWKS fetch and userinfo call) needs more headroom than
# httpx's 5s default, but must stay under the auth-code TTL so a timeout is not
# reported while Vikunja is still completing the exchange.
_VIKUNJA_TIMEOUT_SECONDS = 15.0


def init_federator(provider_name: str) -> None:
    """Build the Vikunja client + session cache and assign the module globals.

    Called once at startup (lifespan) after providers are loaded. Safe to call
    again: the prior httpx client is closed and the cache replaced.
    """
    global _vikunja, _SESSIONS
    import httpx

    provider = get_provider(provider_name)
    if provider is None:
        # Name the file and the key: an AttributeError on `provider.api_base`
        # here names neither, and this is a startup-only failure.
        raise ValueError(
            f"provider {provider_name!r} is not defined in the providers file "
            f"(found: {sorted(PROVIDERS) or 'none'})"
        )
    # Validate BEFORE closing: raising after the close would leave _vikunja
    # holding an already-closed httpx client.
    if _vikunja is not None:
        _vikunja._client.close()  # release the prior pool on re-init
    _vikunja = VikunjaClient(
        provider,
        httpx.Client(base_url=provider.api_base, timeout=_VIKUNJA_TIMEOUT_SECONDS),
    )
    _SESSIONS = SessionCache(margin=60.0)


def _extract_bearer(headers: dict) -> str | None:
    """Pull the incoming `Authorization: Bearer <token>` off the request headers,
    if present. Returns the stripped token, or None."""
    auth = headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip() or None
    return None


def _deny(retryable: bool):
    """Federation-failure deny shape. 503 for retryable (Vikunja unreachable/5xx)
    so clients can retry; 401 for terminal (4xx). Both keep PERMISSION_DENIED at
    the gRPC status and the existing `{"error": "Unauthorized"}` body.

    NOTE: the Frigate/mTLS deny path below still uses 403 Forbidden; consider
    aligning it with this 401/503 scheme in a future change. Do NOT change the
    Frigate path now.
    """
    code = (
        http_status_pb2.StatusCode.ServiceUnavailable
        if retryable
        else http_status_pb2.StatusCode.Unauthorized
    )
    return external_auth_pb2.CheckResponse(
        status=status_pb2.Status(code=code_pb2.PERMISSION_DENIED),
        denied_response=external_auth_pb2.DeniedHttpResponse(
            status=http_status_pb2.HttpStatus(code=code),
            body='{"error": "Unauthorized"}',
        ),
    )


def _record_span(
    *,
    allowed: bool,
    host: str,
    path: str,
    frigate_bypass: bool,
    client_cert: x509.Certificate | None,
) -> None:
    """Annotate the current span with the authz decision (best-effort).

    A tracing failure must never affect the decision, so everything here is
    wrapped and swallowed. When telemetry is disabled or the span is sampled
    out, it returns early since the span is not recording.
    """
    span = trace.get_current_span()
    if not span.is_recording():
        return
    try:
        span.set_attribute("authz.allowed", allowed)
        span.set_attribute("authz.host", host)
        span.set_attribute("authz.path", path)
        span.set_attribute("authz.frigate_metrics_bypass", frigate_bypass)
        if client_cert is not None:
            identity = parse_client_identity(client_cert).model_dump(exclude_none=True)
            for key, value in identity.items():
                # Skip empty lists; OTel rejects ambiguous empty sequences.
                if isinstance(value, list) and not value:
                    continue
                span.set_attribute(f"authz.identity.{key}", value)
    except Exception:
        logger.exception("Failed to record authz span attributes")


class AuthorizationService(external_auth_pb2_grpc.AuthorizationServicer):
    """Simple Envoy External Authorization Service"""

    def __init__(self, config: Config):
        self._config = config

    def Check(self, request, context):
        """Entry point called by Envoy to authorize a request"""

        headers = dict(request.attributes.request.http.headers)
        path = request.attributes.request.http.path

        logger.info(
            "Request received",
            extra={
                "host": request.attributes.request.http.host,
                "path": path,
                "principal": request.attributes.source.principal,
            },
        )
        # Guarded: the redaction comprehension is an argument expression, so
        # without this check it runs on every request to build a string that
        # INFO-level logging then discards.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Headers: %s",
                {
                    k: "***" if k.lower() in _SENSITIVE_HEADERS else v
                    for k, v in headers.items()
                },
            )

        # Verify the client cert once (if provided) and reuse the result.
        raw_certificate = request.attributes.source.certificate
        client_cert = None
        if raw_certificate:
            client_cert = verify_client_cert(
                urllib.parse.unquote(raw_certificate),
                self._config.ha_ca_store,
            )

        # Figure out if a request should be allowed (can be arbitrary criteria)
        frigate_metrics_bypass = (
            # Requests to the frigate metrics endpoint don't need auth
            request.attributes.request.http.host == FRIGATE_HOST
            and path == "/api/metrics"
        )
        allowed = frigate_metrics_bypass or (
            # Requests should contain a valid client certificate from the
            # Home Assistant CA
            client_cert is not None
        )

        _record_span(
            allowed=allowed,
            host=request.attributes.request.http.host,
            path=path,
            frigate_bypass=frigate_metrics_bypass,
            client_cert=client_cert,
        )

        if allowed:
            log_extra: dict = {}
            # Parsing is best-effort and must never affect the decision. The
            # parsed identity is reused for subject derivation below so the cert
            # attributes are only walked once per request.
            identity = None
            if client_cert is not None:
                try:
                    identity = parse_client_identity(client_cert)
                    log_extra["identity"] = identity.model_dump(exclude_none=True)
                except Exception:
                    logger.exception("Failed to parse client identity")
            logger.info("✓ Authorized", extra=log_extra)

            return_headers: list[HeaderValueOption] = []
            host = request.attributes.request.http.host

            # For allowed requests to Frigate, add the trusted proxy token header
            # which Frigate looks for to determine if the request is from an
            # authorized proxy. The Frigate path is orthogonal to federation:
            # get_bearer must NOT be called here.
            if host == FRIGATE_HOST:
                return_headers.append(
                    HeaderValueOption(
                        header=HeaderValue(
                            key="X-Proxy-Secret",
                            value=self._config.frigate_proxy_secret,
                        ),
                    )
                )
            elif (
                # Federate only for a host a provider explicitly CLAIMS. An
                # allowlist, not "everything that is not Frigate": otherwise
                # attaching this ext_authz to an unrelated vhost would silently
                # start injecting a Vikunja bearer over that client's own
                # credential. A host no provider claims is allowed through
                # untouched.
                _vikunja is not None
                and _SESSIONS is not None
                and client_cert is not None
                and provider_for_host(host) is not None
            ):
                try:
                    # identity may be None here if the best-effort parse above
                    # failed; derive_subject would then re-parse the same cert
                    # unprotected, so failures must not escape this block and
                    # crash the RPC (parsing must never affect the decision).
                    subject = derive_subject(client_cert, identity)
                except Exception:
                    logger.exception("Failed to derive subject for federation")
                    return _deny(retryable=False)
                incoming_bearer = _extract_bearer(headers)
                try:
                    upstream = get_bearer(subject, incoming_bearer, _vikunja, _SESSIONS)
                except DownstreamError as exc:
                    logger.warning("denied-federation-failure sub=%s", subject.sub)
                    return _deny(exc.retryable)
                if upstream is not None:
                    return_headers.append(
                        HeaderValueOption(
                            header=HeaderValue(
                                key="Authorization",
                                value=f"Bearer {upstream}",
                            ),
                        )
                    )
                    logger.info("injected-bearer sub=%s", subject.sub)
                else:
                    logger.info("allowed-through-client-bearer sub=%s", subject.sub)

            return external_auth_pb2.CheckResponse(
                status=status_pb2.Status(code=code_pb2.OK),
                ok_response=external_auth_pb2.OkHttpResponse(
                    headers=return_headers,
                ),
            )
        else:
            logger.info("✗ Denied")
            return external_auth_pb2.CheckResponse(
                status=status_pb2.Status(code=code_pb2.PERMISSION_DENIED),
                denied_response=external_auth_pb2.DeniedHttpResponse(
                    status=http_status_pb2.HttpStatus(
                        code=http_status_pb2.StatusCode.Forbidden
                    ),
                    body='{"error": "Unauthorized"}',
                ),
            )


def register_services(server: grpc.Server, config: Config) -> health.HealthServicer:
    """Register the authz + health servicers on `server`.

    Returns the health servicer so the caller can flip SERVING/NOT_SERVING
    around start/stop.
    """
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        AuthorizationService(config), server
    )
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    return health_servicer
