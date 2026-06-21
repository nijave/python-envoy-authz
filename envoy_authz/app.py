import datetime
import logging
import os
import sys
import urllib.parse
from concurrent import futures
from dataclasses import dataclass

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto
from envoy.config.core.v3.base_pb2 import HeaderValueOption, HeaderValue
from envoy.service.auth.v3 import external_auth_pb2
from envoy.service.auth.v3 import external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2, status_pb2
from pythonjsonlogger import json as jsonlogger

handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(jsonlogger.JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)


@dataclass
class Config:
    frigate_proxy_secret: str
    # Shared across the gRPC thread pool; must not be mutated after the
    # server starts (concurrent reads during cert verification are safe).
    ha_ca_store: crypto.X509Store


FRIGATE_HOST = "frigate.apps.somemissing.info"


def configure_crl(store: crypto.X509Store, crl_pem: str) -> bool:
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    if crl.next_update_utc <= datetime.datetime.now(datetime.timezone.utc):
        logger.warning("CRL is expired (next_update=%s), skipping", crl.next_update_utc)
        return False
    store.add_crl(crl)
    store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
    logger.info("CRL loaded (next_update=%s)", crl.next_update_utc)
    return True


def build_store(ca_cert_pem: str, crl_pem: str | None = None) -> crypto.X509Store:
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem.encode())
    store = crypto.X509Store()
    store.add_cert(ca_cert)
    if crl_pem:
        configure_crl(store, crl_pem)
    return store


def load_config() -> Config:
    return Config(
        frigate_proxy_secret=os.environ["FRIGATE_X_PROXY_SECRET"],
        ha_ca_store=build_store(
            os.environ["HA_CA_CERTIFICATE"],
            os.environ.get("HA_CRL"),
        ),
    )


def verify_client_cert(cert_pem: str, store: crypto.X509Store) -> bool:
    """
    Verify client certificate against CA.
    """
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())
        crypto.X509StoreContext(store, cert).verify_certificate()

        eku = cert.to_cryptography().extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        )
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
            return False

        return True
    except Exception:
        logger.exception("Client cert verification failed")
        return False


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
        logger.debug("Headers: %s", headers)

        # Figure out if a request should be allowed (can be arbitrary criteria)
        allowed = (
            # Requests to the frigate metrics endpoint don't need auth
            request.attributes.request.http.host == FRIGATE_HOST
            and path == "/api/metrics"
        ) or (
            # Requests should contain a valid client certificate from the Home Assistant CA
            verify_client_cert(
                urllib.parse.unquote(request.attributes.source.certificate),
                self._config.ha_ca_store,
            )
        )

        if allowed:
            logger.info("✓ Authorized")

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


if __name__ == "__main__":
    config = load_config()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))

    # Register services
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        AuthorizationService(config), server
    )
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    # Load TLS credentials
    with open("/var/lib/tls/tls.key", "rb") as f:
        private_key = f.read()
    with open("/var/lib/tls/tls.crt", "rb") as f:
        certificate_chain = f.read()

    server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])

    server.add_secure_port("[::]:5000", server_credentials)

    logger.info("Starting secure gRPC server on port 5000...")
    server.start()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    server.wait_for_termination()
