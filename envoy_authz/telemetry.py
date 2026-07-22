"""OpenTelemetry tracing setup for envoy_authz.

Opt-in: unless ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set (and ``OTEL_SDK_DISABLED``
is not ``"true"``), :func:`setup_telemetry` is a no-op and the global tracer
stays the default no-op provider. Enabling is purely env-driven; no endpoint is
hardcoded here. The OTLP exporter reads its endpoint/headers/timeout from the
standard ``OTEL_EXPORTER_OTLP_*`` environment variables.
"""

import logging
import os
from importlib.metadata import PackageNotFoundError, version

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.grpc import GrpcInstrumentorServer
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

logger = logging.getLogger(__name__)

DEFAULT_SERVICE_NAME = "python-envoy-authz"


def _service_version() -> str:
    try:
        return version("envoy-authz")
    except PackageNotFoundError:
        return "0.0.0"


def _telemetry_enabled() -> bool:
    """True iff OTLP export is configured and the SDK is not disabled."""
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        return False
    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))


def build_tracer_provider() -> TracerProvider:
    """Build a TracerProvider with an OTLP/gRPC batch exporter.

    Does not touch global state; caller installs it via ``setup_telemetry``.
    """
    resource = Resource.create(
        {
            SERVICE_NAME: os.environ.get("OTEL_SERVICE_NAME", DEFAULT_SERVICE_NAME),
            SERVICE_VERSION: _service_version(),
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    return provider


def setup_telemetry() -> TracerProvider | None:
    """Install a global OTLP TracerProvider when telemetry is enabled.

    Returns the provider (also set as the global provider) when enabled, else
    ``None``. Any failure is logged and treated as disabled — never fatal.
    """
    if not _telemetry_enabled():
        logger.debug("OpenTelemetry disabled (no OTEL_EXPORTER_OTLP_ENDPOINT)")
        return None
    try:
        provider = build_tracer_provider()
        trace.set_tracer_provider(provider)
        logger.info("OpenTelemetry tracing enabled")
        return provider
    except Exception:
        logger.exception("Failed to set up OpenTelemetry; continuing without tracing")
        return None


def instrument_grpc_server() -> None:
    """Patch ``grpc.server`` to auto-create a span per RPC.

    Must run before the gRPC server is constructed.
    """
    GrpcInstrumentorServer().instrument()


def instrument_fastapi(app) -> None:
    """Instrument a FastAPI app instance to auto-create a span per request."""
    FastAPIInstrumentor.instrument_app(app)
