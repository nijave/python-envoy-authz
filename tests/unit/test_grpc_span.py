from unittest.mock import MagicMock

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from envoy_authz.grpc_service import AuthorizationService


def _run_check_in_span(servicer, request):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("Check"):
        servicer.Check(request, MagicMock())
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    return spans[0].attributes


def test_check_span_authorized_carries_identity(
    ha_config, check_request, trusted_client_cert_pem
):
    servicer = AuthorizationService(ha_config)
    request = check_request(
        host="example.somemissing.info",
        path="/",
        client_cert_pem=trusted_client_cert_pem,
    )
    attrs = _run_check_in_span(servicer, request)
    assert attrs["authz.allowed"] is True
    assert attrs["authz.host"] == "example.somemissing.info"
    assert attrs["authz.path"] == "/"
    assert attrs["authz.frigate_metrics_bypass"] is False
    assert (
        attrs["authz.identity.common_name"] == "trusted-client.ha.apps.somemissing.info"
    )
    assert "clientAuth" in attrs["authz.identity.extended_key_usages"]


def test_check_span_denied_has_no_identity(ha_config, check_request):
    servicer = AuthorizationService(ha_config)
    request = check_request(host="example.somemissing.info", path="/")
    attrs = _run_check_in_span(servicer, request)
    assert attrs["authz.allowed"] is False
    assert "authz.identity.common_name" not in attrs
