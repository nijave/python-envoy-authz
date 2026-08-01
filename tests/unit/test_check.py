"""Unit tests for AuthorizationService.Check, including federation.

These exercise the servicer directly (no real gRPC/TLS). The real-TLS gRPC
suite lives in tests/integration/test_check.py and is untouched here.
"""

import logging
import time

import httpx
import respx
from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2

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


@respx.mock
def test_check_injects_federated_bearer(
    grpc_servicer, email_client_cert_pem, monkeypatch
):
    # No incoming bearer, no cache → federate → inject Authorization.
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    import jwt as pyjwt

    bearer = pyjwt.encode(
        {"id": "1", "exp": int(time.time()) + 600, "type": "access"},
        "test-secret-key",
        algorithm="HS256",
    )
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": "vikunja_refresh_token=fresh-rt; HttpOnly"},
            json={"token": bearer},
        )
    )
    req = grpc_servicer.check_request(
        host="vikunja.example.com",
        path="/api/v1",
        client_cert_pem=email_client_cert_pem,
    )
    resp = grpc_servicer.servicer.Check(req, None)
    assert resp.status.code == code_pb2.OK
    added = {h.header.key: h.header.value for h in resp.ok_response.headers}
    assert added["Authorization"] == f"Bearer {bearer}"


def test_check_allows_through_when_get_bearer_returns_none(
    grpc_servicer, email_client_cert_pem, monkeypatch
):
    # get_bearer returns None → OK with NO Authorization header (client's
    # incoming bearer was verified locally).
    from envoy_authz import grpc_service

    monkeypatch.setattr(grpc_service, "get_bearer", lambda *a, **k: None)
    req = grpc_servicer.check_request(
        host="vikunja.example.com",
        path="/api/v1",
        client_cert_pem=email_client_cert_pem,
        bearer="client-bearer",
    )
    resp = grpc_servicer.servicer.Check(req, None)
    assert resp.status.code == code_pb2.OK
    added = {h.header.key: h.header.value for h in resp.ok_response.headers}
    assert "Authorization" not in added


def test_check_denies_503_on_retryable_federation_failure(
    grpc_servicer, email_client_cert_pem, monkeypatch
):
    # Vikunja 5xx → retryable → 503.
    from envoy_authz import grpc_service
    from envoy_authz.federator.vikunja import DownstreamError

    monkeypatch.setattr(
        grpc_service,
        "get_bearer",
        lambda *a, **k: (_ for _ in ()).throw(
            DownstreamError("callback 500", retryable=True)
        ),
    )
    req = grpc_servicer.check_request(
        host="vikunja.example.com",
        path="/api/v1",
        client_cert_pem=email_client_cert_pem,
    )
    resp = grpc_servicer.servicer.Check(req, None)
    assert resp.status.code == code_pb2.PERMISSION_DENIED
    assert (
        resp.denied_response.status.code
        == http_status_pb2.StatusCode.ServiceUnavailable
    )  # 503
    assert resp.denied_response.body == '{"error": "Unauthorized"}'


def test_check_denies_401_on_terminal_federation_failure(
    grpc_servicer, email_client_cert_pem, monkeypatch
):
    # Vikunja 4xx → terminal → 401.
    from envoy_authz import grpc_service
    from envoy_authz.federator.vikunja import DownstreamError

    monkeypatch.setattr(
        grpc_service,
        "get_bearer",
        lambda *a, **k: (_ for _ in ()).throw(
            DownstreamError("callback 403", retryable=False)
        ),
    )
    req = grpc_servicer.check_request(
        host="vikunja.example.com",
        path="/api/v1",
        client_cert_pem=email_client_cert_pem,
    )
    resp = grpc_servicer.servicer.Check(req, None)
    assert resp.status.code == code_pb2.PERMISSION_DENIED
    assert (
        resp.denied_response.status.code == http_status_pb2.StatusCode.Unauthorized
    )  # 401
    assert resp.denied_response.body == '{"error": "Unauthorized"}'


def test_check_denies_401_when_subject_derivation_fails(
    grpc_servicer, email_client_cert_pem, monkeypatch
):
    """Regression: derive_subject's identity re-parse (when the best-effort
    parse earlier in Check already failed) was unprotected, so a raise there
    escaped Check entirely instead of denying — contradicting "parsing is
    best-effort and must never affect the decision" for federation hosts."""
    from envoy_authz import grpc_service

    monkeypatch.setattr(
        grpc_service,
        "derive_subject",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")),
    )
    req = grpc_servicer.check_request(
        host="vikunja.example.com",
        path="/api/v1",
        client_cert_pem=email_client_cert_pem,
    )
    resp = grpc_servicer.servicer.Check(req, None)
    assert resp.status.code == code_pb2.PERMISSION_DENIED
    assert (
        resp.denied_response.status.code == http_status_pb2.StatusCode.Unauthorized
    )  # 401
    assert resp.denied_response.body == '{"error": "Unauthorized"}'


def test_check_frigate_path_still_injects_x_proxy_secret(
    grpc_servicer, trusted_client_cert_pem, frigate_secret, monkeypatch
):
    # Regression: the Frigate path must keep working unchanged (orthogonal to
    # federation). get_bearer must NOT be called on the Frigate path.
    from envoy_authz import grpc_service

    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("get_bearer must not run on the Frigate path")

    monkeypatch.setattr(grpc_service, "get_bearer", _boom)
    req = grpc_servicer.check_request(
        host=grpc_service.FRIGATE_HOST,
        path="/api/other",
        client_cert_pem=trusted_client_cert_pem,
    )
    resp = grpc_servicer.servicer.Check(req, None)
    assert resp.status.code == code_pb2.OK
    added = {h.header.key: h.header.value for h in resp.ok_response.headers}
    assert added["X-Proxy-Secret"] == frigate_secret
    assert called["n"] == 0


def test_unlisted_host_is_allowed_without_injection(
    grpc_servicer, email_client_cert_pem
):
    """Federation is an ALLOWLIST. A host no provider claims must be allowed
    through with NO Authorization header, not federated to Vikunja — otherwise
    attaching this ext_authz to another vhost silently overwrites that client's
    own credential with a Vikunja bearer."""
    req = grpc_servicer.check_request(
        host="home-assistant.apps.somemissing.info",
        path="/api/",
        client_cert_pem=email_client_cert_pem,
        bearer="the-clients-own-token",
    )
    resp = grpc_servicer.servicer.Check(req, None)
    assert resp.status.code == code_pb2.OK
    assert [h.header.key for h in resp.ok_response.headers] == []


def test_init_federator_names_the_missing_provider(tmp_path):
    """A renamed providers.yaml key used to die on `NoneType.api_base`, naming
    neither the file nor the key."""
    import pytest

    from envoy_authz.federator import providers
    from envoy_authz.grpc_service import init_federator

    p = tmp_path / "providers.yaml"
    p.write_text(
        "providers:\n"
        "  vikunja-prod:\n"
        '    hosts: ["vikunja.example.com"]\n'
        '    client_id: "vikunja"\n'
        '    client_secret: "s"\n'
        '    redirect_url: "http://localhost:3456/cb"\n'
        '    api_base: "http://localhost:3456"\n'
        '    provider_key: "broker"\n'
    )
    providers.load_providers(str(p))
    with pytest.raises(ValueError) as exc:
        init_federator("vikunja")
    assert "vikunja" in str(exc.value)
    assert "vikunja-prod" in str(exc.value)
