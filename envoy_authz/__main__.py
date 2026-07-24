import asyncio
import contextlib
import logging
from concurrent import futures

import grpc
import uvicorn
from fastapi import FastAPI
from grpc_health.v1 import health, health_pb2

from . import grpc_service
from .config import Config, load_config
from .grpc_service import register_services
from .http_app import create_app

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


def _teardown_federator() -> None:
    """Release the federator's httpx pool + session cache, if wired.

    Reads the live module globals (not import-time values) since init_federator
    assigns them.
    """
    if grpc_service._vikunja is not None:
        grpc_service._vikunja._client.close()
        grpc_service._vikunja = None
    if grpc_service._SESSIONS is not None:
        grpc_service._SESSIONS.clear()
        grpc_service._SESSIONS = None


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    """Load providers, seed the OP store, wire the federator, then run the gRPC
    server lifecycle. Tears the federator's httpx client + session cache down on
    shutdown.

    Federation is opt-in: with no IDP_ISSUER / SECRET_KEY / PROVIDERS_FILE the
    federator is not wired and the service runs as the mTLS + Frigate gate it
    was before, which is what keeps the pre-federation deployment working.
    """
    config = load_config()
    settings = config.settings
    federation = settings.federation()

    if federation is not None:
        # 1. Load providers + seed the OP store (clients from providers.yaml).
        from .federator import providers
        from .federator.store import _reset, seed

        providers.load_providers(federation.providers_file)
        _reset()
        seed()

        # 2. Wire the federator module globals (VikunjaClient + SessionCache).
        grpc_service.init_federator("vikunja")
    else:
        logger.info(
            "Federation disabled (set IDP_ISSUER, SECRET_KEY and PROVIDERS_FILE "
            "to enable); serving the mTLS + Frigate authorization gate only"
        )

    # 3. gRPC server lifecycle (preserved from the original lifespan).
    try:
        server, health_servicer = build_grpc_server(config)
    except BaseException:
        # e.g. missing TLS material. Don't leak the pool init_federator opened.
        _teardown_federator()
        raise
    try:
        server.start()
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        logger.info("Secure gRPC server started on port %s", settings.grpc_port)
        app.state.config = config
        yield
    finally:
        logger.info("Draining gRPC server...")
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        stopped = server.stop(grace=10)
        await asyncio.to_thread(stopped.wait)
        _teardown_federator()


def main():
    config = load_config()
    s = config.settings
    app = create_app(
        lifespan=lifespan,
        op_key_path=s.op_key_path,
        federation=s.federation(),
    )
    logger.info("Starting HTTPS server on port %s", s.http_port)
    uvicorn.run(
        app,
        host="::",
        port=s.http_port,
        ssl_certfile=s.tls_cert_path,
        ssl_keyfile=s.tls_key_path,
        log_config=None,
    )


if __name__ == "__main__":
    main()
