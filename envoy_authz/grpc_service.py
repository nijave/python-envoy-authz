import logging
import urllib.parse

import grpc
from grpc_health.v1 import health, health_pb2_grpc
from envoy.config.core.v3.base_pb2 import HeaderValueOption, HeaderValue
from envoy.service.auth.v3 import external_auth_pb2
from envoy.service.auth.v3 import external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2, status_pb2

from envoy_authz.identity import parse_client_identity

from .config import Config, verify_client_cert

logger = logging.getLogger(__name__)

FRIGATE_HOST = "frigate.apps.somemissing.info"

# Headers never emitted to logs (they may carry a bearer / refresh cookie).
_SENSITIVE_HEADERS = frozenset(("authorization", "proxy-authorization", "cookie"))


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
        allowed = (
            # Requests to the frigate metrics endpoint don't need auth
            request.attributes.request.http.host == FRIGATE_HOST
            and path == "/api/metrics"
        ) or (
            # Requests should contain a valid client certificate from the
            # Home Assistant CA
            client_cert is not None
        )

        if allowed:
            log_extra: dict = {}
            # Parsing is best-effort and must never affect the decision.
            if client_cert is not None:
                try:
                    log_extra["identity"] = parse_client_identity(
                        client_cert
                    ).model_dump(exclude_none=True)
                except Exception:
                    logger.exception("Failed to parse client identity")
            logger.info("✓ Authorized", extra=log_extra)

            return_headers: list[HeaderValueOption] = []

            # For allowed requests to Frigate, add the trusted proxy token header
            # which Frigate looks for to determine if the request is from an authorized
            # proxy
            if request.attributes.request.http.host == FRIGATE_HOST:
                return_headers.append(
                    HeaderValueOption(
                        header=HeaderValue(
                            key="X-Proxy-Secret",
                            value=self._config.frigate_proxy_secret,
                        ),
                    )
                )

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
