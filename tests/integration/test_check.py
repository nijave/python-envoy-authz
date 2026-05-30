"""Integration tests for AuthorizationService.Check over real gRPC + TLS."""

from envoy.type.v3 import http_status_pb2
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
    response = stub.Check(check_request(host=FRIGATE_HOST, path="/api/metrics"))

    assert response.status.code == code_pb2.OK
    assert _header_value(response, "X-Proxy-Secret") == frigate_secret


def test_frigate_with_valid_cert_injects_secret(
    stub, check_request, trusted_client_cert_pem, frigate_secret
):
    response = stub.Check(
        check_request(
            host=FRIGATE_HOST,
            path="/api/other",
            client_cert_pem=trusted_client_cert_pem,
        )
    )

    assert response.status.code == code_pb2.OK
    assert _header_value(response, "X-Proxy-Secret") == frigate_secret


def test_other_host_with_valid_cert_no_header(
    stub, check_request, trusted_client_cert_pem
):
    response = stub.Check(
        check_request(
            host="other.example.com",
            path="/any",
            client_cert_pem=trusted_client_cert_pem,
        )
    )

    assert response.status.code == code_pb2.OK
    assert _header_value(response, "X-Proxy-Secret") is None


def _assert_denied(response) -> None:
    assert response.status.code == code_pb2.PERMISSION_DENIED
    assert response.denied_response.status.code == http_status_pb2.StatusCode.Forbidden
    assert response.denied_response.body == '{"error": "Unauthorized"}'


def test_no_cert_on_non_metrics_denied(stub, check_request):
    response = stub.Check(check_request(host=FRIGATE_HOST, path="/api/events"))
    _assert_denied(response)


def test_wrong_path_on_frigate_without_cert_denied(stub, check_request):
    response = stub.Check(check_request(host=FRIGATE_HOST, path="/api/metrics_extra"))
    _assert_denied(response)


def test_wrong_host_on_metrics_path_denied(stub, check_request):
    response = stub.Check(
        check_request(host="not-frigate.example.com", path="/api/metrics")
    )
    _assert_denied(response)


def test_cert_signed_by_different_ca_denied(
    stub, check_request, untrusted_client_cert_pem
):
    response = stub.Check(
        check_request(
            host="other.example.com",
            path="/",
            client_cert_pem=untrusted_client_cert_pem,
        )
    )
    _assert_denied(response)


def test_malformed_cert_denied(stub, check_request):
    response = stub.Check(
        check_request(
            host="other.example.com",
            path="/",
            client_cert_pem="not-a-cert",
        )
    )
    _assert_denied(response)


def test_self_signed_client_cert_denied(
    stub, check_request, self_signed_client_cert_pem
):
    response = stub.Check(
        check_request(
            host="other.example.com",
            path="/",
            client_cert_pem=self_signed_client_cert_pem,
        )
    )
    _assert_denied(response)


def test_wrong_eku_client_cert_denied(stub, check_request, wrong_eku_client_cert_pem):
    """A cert signed by the trusted CA but with serverAuth (not clientAuth)
    EKU must be rejected."""
    response = stub.Check(
        check_request(
            host="other.example.com",
            path="/",
            client_cert_pem=wrong_eku_client_cert_pem,
        )
    )
    _assert_denied(response)
