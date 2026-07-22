"""Integration tests for AuthorizationService.Check over real gRPC + TLS."""

from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2

from envoy_authz.app import FRIGATE_HOST


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


def test_authorized_cert_logs_identity(
    stub, check_request, trusted_client_cert_pem, caplog
):
    """A verified client cert produces an Authorized log line whose extra
    carries the parsed identity (common_name + clientAuth EKU)."""
    import logging

    with caplog.at_level(logging.INFO, logger="envoy_authz.grpc_service"):
        response = stub.Check(
            check_request(
                host="other.example.com",
                path="/",
                client_cert_pem=trusted_client_cert_pem,
            )
        )

    assert response.status.code == code_pb2.OK
    identity_records = [
        r for r in caplog.records if getattr(r, "identity", None) is not None
    ]
    assert identity_records, "expected an Authorized log record with identity"
    identity = identity_records[-1].identity
    assert identity["common_name"] == "trusted-client.ha.apps.somemissing.info"
    assert "clientAuth" in identity["extended_key_usages"]


def test_authorized_cert_parse_failure_does_not_deny(
    stub, check_request, trusted_client_cert_pem, caplog, monkeypatch
):
    """If identity parsing raises, the request must still be authorized and the
    failure logged — parsing is best-effort and never affects the decision."""
    import logging

    from envoy_authz import grpc_service

    def _boom(_cert):
        raise RuntimeError("boom")

    monkeypatch.setattr(grpc_service, "parse_client_identity", _boom)

    with caplog.at_level(logging.INFO, logger="envoy_authz.grpc_service"):
        response = stub.Check(
            check_request(
                host="other.example.com",
                path="/",
                client_cert_pem=trusted_client_cert_pem,
            )
        )

    assert response.status.code == code_pb2.OK
    assert any(
        "Failed to parse client identity" in r.getMessage() for r in caplog.records
    )


def test_revoked_client_cert_denied(stub, check_request, revoked_client_cert_pem):
    """A cert signed by the trusted CA but listed in the CRL must be rejected."""
    response = stub.Check(
        check_request(
            host="other.example.com",
            path="/",
            client_cert_pem=revoked_client_cert_pem,
        )
    )
    _assert_denied(response)
