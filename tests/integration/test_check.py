"""Integration tests for AuthorizationService.Check over real gRPC + TLS."""

from google.rpc import code_pb2


FRIGATE_HOST = "frigate.apps.somemissing.info"


def _header_value(response, key: str) -> str | None:
    for h in response.ok_response.headers:
        if h.header.key == key:
            return h.header.value
    return None


def test_frigate_metrics_no_cert_allowed(stub, check_request, frigate_secret):
    """The /api/metrics path is allowed without a client cert, and the
    app still injects X-Proxy-Secret because Frigate's metrics endpoint
    requires the header to be present on every upstream request."""
    response = stub.Check(
        check_request(host=FRIGATE_HOST, path="/api/metrics")
    )

    assert response.status.code == code_pb2.OK
    assert _header_value(response, "X-Proxy-Secret") == frigate_secret
