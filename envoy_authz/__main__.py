import asyncio
import contextlib
import logging
from concurrent import futures

import grpc
import uvicorn
from fastapi import FastAPI
from grpc_health.v1 import health, health_pb2

from .config import Config, load_config
from .grpc_service import register_services
from .http_app import create_app
from .telemetry import (
    instrument_fastapi,
    instrument_grpc_server,
    setup_telemetry,
)

logger = logging.getLogger(__name__)


def build_grpc_server(config: Config) -> tuple[grpc.Server, health.HealthServicer]:
    s = config.settings
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_servicer = register_services(server, config)

    with open(s.tls_key_path, "rb") as f:
        private_key = f.read()
    with open(s.tls_cert_path, "rb") as f:
        certificate_chain = f.read()

    credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
    server.add_secure_port(f"[::]:{s.grpc_port}", credentials)
    return server, health_servicer


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    server, health_servicer = build_grpc_server(config)
    try:
        server.start()
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        logger.info("Secure gRPC server started on port %s", config.settings.grpc_port)
        app.state.config = config
        yield
    finally:
        logger.info("Draining gRPC server...")
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        stopped = server.stop(grace=10)
        await asyncio.to_thread(stopped.wait)
        provider = getattr(app.state, "tracer_provider", None)
        if provider is not None:
            provider.shutdown()


def main():
    provider = setup_telemetry()
    if provider is not None:
        # Must patch grpc.server before build_grpc_server runs in the lifespan.
        instrument_grpc_server()
    app = create_app(lifespan=lifespan)
    if provider is not None:
        instrument_fastapi(app)
    app.state.tracer_provider = provider
    config = load_config()
    s = config.settings
    logger.info("Starting HTTPS server on port %s", s.http_port)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=s.http_port,
        ssl_certfile=s.tls_cert_path,
        ssl_keyfile=s.tls_key_path,
        log_config=None,
    )


if __name__ == "__main__":
    main()
