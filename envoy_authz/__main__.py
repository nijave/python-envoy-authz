import asyncio
import contextlib
import logging
import os
from concurrent import futures

import grpc
import uvicorn
from fastapi import FastAPI
from grpc_health.v1 import health, health_pb2

from .config import Config, load_config
from .grpc_service import register_services
from .http_app import create_app

logger = logging.getLogger(__name__)

GRPC_PORT = int(os.environ.get("GRPC_PORT", "5000"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "5001"))
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/var/lib/tls/tls.crt")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/var/lib/tls/tls.key")


def build_grpc_server(config: Config) -> tuple[grpc.Server, health.HealthServicer]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_servicer = register_services(server, config)

    with open(TLS_KEY_PATH, "rb") as f:
        private_key = f.read()
    with open(TLS_CERT_PATH, "rb") as f:
        certificate_chain = f.read()

    credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
    server.add_secure_port(f"[::]:{GRPC_PORT}", credentials)
    return server, health_servicer


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    server, health_servicer = build_grpc_server(config)
    try:
        server.start()
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        logger.info("Secure gRPC server started on port %s", GRPC_PORT)
        app.state.config = config
        yield
    finally:
        logger.info("Draining gRPC server...")
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        stopped = server.stop(grace=10)
        await asyncio.to_thread(stopped.wait)


def main():
    app = create_app(lifespan=lifespan)
    logger.info("Starting HTTPS server on port %s", HTTP_PORT)
    uvicorn.run(
        app,
        host="::",
        port=HTTP_PORT,
        ssl_certfile=TLS_CERT_PATH,
        ssl_keyfile=TLS_KEY_PATH,
        log_config=None,
    )


if __name__ == "__main__":
    main()
