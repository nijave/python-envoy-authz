"""Unit tests for the gRPC `Check` handler."""

import logging

from envoy_authz.grpc_service import AuthorizationService


def test_check_redacts_sensitive_headers_from_the_debug_log(
    ha_config, check_request, trusted_client_cert_pem, caplog
):
    """The `Headers: …` DEBUG line must never emit a credential verbatim.

    Envoy forwards the client's own `Authorization` / `Cookie` headers on every
    request, so logging the header dict as-is writes bearer tokens and session
    cookies to the log at DEBUG.
    """
    request = check_request(
        host="home.apps.somemissing.info",
        path="/api/v1",
        client_cert_pem=trusted_client_cert_pem,
    )
    request.attributes.request.http.headers["authorization"] = (
        "Bearer s3cret-bearer-value"
    )
    request.attributes.request.http.headers["cookie"] = "jwt=s3cret-cookie-value"
    request.attributes.request.http.headers["proxy-authorization"] = (
        "Basic s3cret-basic"
    )
    request.attributes.request.http.headers["x-request-id"] = "not-a-secret"

    caplog.set_level(logging.DEBUG, logger="envoy_authz.grpc_service")
    AuthorizationService(ha_config).Check(request, None)

    messages = [record.getMessage() for record in caplog.records]
    header_logs = [message for message in messages if message.startswith("Headers:")]
    # Assert the line is still emitted, so deleting it cannot pass this test
    # vacuously, and that only the sensitive values were replaced.
    assert len(header_logs) == 1
    assert "***" in header_logs[0]
    assert "not-a-secret" in header_logs[0]
    for message in messages:
        assert "s3cret-bearer-value" not in message
        assert "s3cret-cookie-value" not in message
        assert "s3cret-basic" not in message
