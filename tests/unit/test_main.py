import asyncio
import types
from unittest.mock import MagicMock

from grpc_health.v1 import health_pb2

from envoy_authz import __main__ as main_module


def _fake_config():
    """A Config stand-in carrying everything main() and the lifespan read off
    settings, so neither has to touch the real environment."""
    return types.SimpleNamespace(
        settings=types.SimpleNamespace(
            grpc_port=5000,
            http_port=5001,
            tls_cert_path="/var/lib/tls/tls.crt",
            tls_key_path="/var/lib/tls/tls.key",
        )
    )


def test_lifespan_starts_and_drains_grpc_server(monkeypatch):
    fake_config = _fake_config()
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


def test_main_sets_up_and_instruments_when_enabled(monkeypatch):
    fake_provider = MagicMock()
    calls = []
    fake_app = MagicMock()
    run = MagicMock()

    monkeypatch.setattr(main_module, "setup_telemetry", lambda: fake_provider)
    monkeypatch.setattr(
        main_module, "instrument_grpc_server", lambda: calls.append("grpc")
    )
    monkeypatch.setattr(
        main_module, "instrument_fastapi", lambda app: calls.append("fastapi")
    )
    monkeypatch.setattr(main_module, "load_config", _fake_config)
    monkeypatch.setattr(main_module, "create_app", lambda lifespan: fake_app)
    monkeypatch.setattr(main_module.uvicorn, "run", run)

    main_module.main()

    # gRPC instrumentor runs before FastAPI (must patch grpc.server pre-build).
    assert calls == ["grpc", "fastapi"]
    assert fake_app.state.tracer_provider is fake_provider
    assert run.call_args.kwargs["host"] == "0.0.0.0"


def test_main_skips_instrumentation_when_disabled(monkeypatch):
    calls = []
    fake_app = MagicMock()

    monkeypatch.setattr(main_module, "setup_telemetry", lambda: None)
    monkeypatch.setattr(
        main_module, "instrument_grpc_server", lambda: calls.append("grpc")
    )
    monkeypatch.setattr(
        main_module, "instrument_fastapi", lambda app: calls.append("fastapi")
    )
    monkeypatch.setattr(main_module, "load_config", _fake_config)
    monkeypatch.setattr(main_module, "create_app", lambda lifespan: fake_app)
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)

    main_module.main()

    assert calls == []
    assert fake_app.state.tracer_provider is None


def test_lifespan_flushes_tracer_provider(monkeypatch):
    fake_config = _fake_config()
    fake_server = MagicMock()
    fake_health = MagicMock()
    fake_provider = MagicMock()

    monkeypatch.setattr(main_module, "load_config", lambda: fake_config)
    monkeypatch.setattr(
        main_module, "build_grpc_server", lambda config: (fake_server, fake_health)
    )

    app = MagicMock()
    app.state.tracer_provider = fake_provider

    async def run():
        async with main_module.lifespan(app):
            pass

    asyncio.run(run())

    fake_provider.shutdown.assert_called_once_with()
