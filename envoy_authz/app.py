import logging
import signal
from concurrent import futures

import grpc
from grpc_health.v1 import health_pb2

from .config import (  # noqa: F401  (re-exported for tests/back-compat)
    Config,
    build_store,
    configure_crl,
    load_config,
    verify_client_cert,
)
from .grpc_service import (  # noqa: F401
    FRIGATE_HOST,
    AuthorizationService,
    register_services,
)

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    config = load_config()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_servicer = register_services(server, config)

    with open("/var/lib/tls/tls.key", "rb") as f:
        private_key = f.read()
    with open("/var/lib/tls/tls.crt", "rb") as f:
        certificate_chain = f.read()

    server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
    server.add_secure_port("[::]:5000", server_credentials)

    logger.info("Starting secure gRPC server on port 5000...")
    server.start()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)

    def _shutdown(signum, _frame):
        logger.info("Received signal %s, draining...", signum)
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        server.stop(grace=10)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server.wait_for_termination()
