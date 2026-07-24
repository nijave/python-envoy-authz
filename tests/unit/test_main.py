import asyncio
from unittest.mock import MagicMock

from grpc_health.v1 import health_pb2

from envoy_authz import __main__ as main_module


def test_lifespan_starts_and_drains_grpc_server(monkeypatch):
    class _Settings:
        grpc_port = 5000

    class _Config:
        settings = _Settings()

    fake_config = _Config()
    fake_server = MagicMock()
    fake_health = MagicMock()

    monkeypatch.setattr(main_module, "load_config", lambda: fake_config)
    monkeypatch.setattr(
        main_module, "build_grpc_server", lambda config: (fake_server, fake_health)
    )

    app = MagicMock()

    async def run():
        async with main_module.lifespan(app):
            # On enter: gRPC server started and marked SERVING.
            fake_server.start.assert_called_once()
            fake_health.set.assert_called_once_with(
                "", health_pb2.HealthCheckResponse.SERVING
            )
            fake_health.set.reset_mock()

    asyncio.run(run())

    # On exit: health flipped to NOT_SERVING and server stopped with grace.
    fake_health.set.assert_called_once_with(
        "", health_pb2.HealthCheckResponse.NOT_SERVING
    )
    fake_server.stop.assert_called_once_with(grace=10)
