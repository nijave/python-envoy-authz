import logging
import os
import sys
import typing
import urllib.parse
from concurrent import futures

import grpc
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

FRIGATE_X_PROXY_SECRET = os.environ["FRIGATE_X_PROXY_SECRET"]

ca_cert = crypto.load_certificate(
    crypto.FILETYPE_PEM,
    os.environ["HA_CA_CERTIFICATE"].encode(),
)
HA_CA_STORE = crypto.X509Store()
HA_CA_STORE.add_cert(ca_cert)


def verify_client_cert(cert_pem: str) -> bool:
    """
    Verify client certificate against CA.
    """
    try:
        crypto.X509StoreContext(
            HA_CA_STORE,
            crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode()),
        ).verify_certificate()
        return True
    except Exception as e:
        logger.info("%s", type(e).__name__)
        return False


class AuthorizationService(external_auth_pb2_grpc.AuthorizationServicer):
    """Simple Envoy External Authorization Service"""

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
            request.attributes.request.http.host == "frigate.apps.somemissing.info"
            and path == "/api/metrics"
        ) or (
            # Requests should contain a valid client certificate from the Home Assistant CA
            verify_client_cert(
                urllib.parse.unquote(request.attributes.source.certificate)
            )
        )

        if allowed:
            logger.info("✓ Authorized")

            return_headers: list[HeaderValueOption] = []

            # For allowed requests to Frigate, add the trusted proxy token header
            # which Frigate looks for to determine if the request is from an authorized
            # proxy
            if request.attributes.request.http.host == "frigate.apps.somemissing.info":
                return_headers.append(
                    HeaderValueOption(
                        header=HeaderValue(
                            key="X-Proxy-Secret",
                            value=FRIGATE_X_PROXY_SECRET,
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
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))

    # Register service
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        AuthorizationService(), server
    )

    # Load TLS credentials
    with open("/var/lib/tls/tls.key", "rb") as f:
        private_key = f.read()
    with open("/var/lib/tls/tls.crt", "rb") as f:
        certificate_chain = f.read()

    server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])

    server.add_secure_port("[::]:5000", server_credentials)

    logger.info("Starting secure gRPC server on port 5000...")
    server.start()
    server.wait_for_termination()
