from unittest.mock import MagicMock

from opentelemetry.sdk.resources import SERVICE_NAME
from opentelemetry.sdk.trace import TracerProvider

from envoy_authz import telemetry


def test_disabled_when_no_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert telemetry._telemetry_enabled() is False


def test_disabled_when_sdk_disabled(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert telemetry._telemetry_enabled() is False


def test_enabled_when_endpoint_set(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert telemetry._telemetry_enabled() is True


def test_setup_returns_none_when_disabled(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    called = []
    monkeypatch.setattr(
        telemetry.trace, "set_tracer_provider", lambda p: called.append(p)
    )
    assert telemetry.setup_telemetry() is None
    assert called == []  # global provider left untouched


def test_setup_builds_and_installs_provider_when_enabled(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    installed = []
    monkeypatch.setattr(
        telemetry.trace, "set_tracer_provider", lambda p: installed.append(p)
    )
    provider = telemetry.setup_telemetry()
    assert isinstance(provider, TracerProvider)
    assert installed == [provider]


def test_build_provider_sets_default_service_name(monkeypatch):
    monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)
    provider = telemetry.build_tracer_provider()
    assert provider.resource.attributes[SERVICE_NAME] == "python-envoy-authz"


def test_setup_failure_is_non_fatal(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)

    def boom():
        raise RuntimeError("no exporter")

    monkeypatch.setattr(telemetry, "build_tracer_provider", boom)
    assert telemetry.setup_telemetry() is None  # swallowed, returns None


def test_instrument_fastapi_marks_app():
    from fastapi import FastAPI

    app = FastAPI()
    telemetry.instrument_fastapi(app)
    assert getattr(app, "_is_instrumented_by_opentelemetry", False) is True


def test_instrument_grpc_server_invokes_instrumentor(monkeypatch):
    instance = MagicMock()
    monkeypatch.setattr(telemetry, "GrpcInstrumentorServer", lambda: instance)
    telemetry.instrument_grpc_server()
    instance.instrument.assert_called_once_with()
