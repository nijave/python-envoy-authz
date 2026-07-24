import pytest
from pydantic import ValidationError


def test_settings_requires_required_fields(monkeypatch):
    from envoy_authz.config import Settings

    monkeypatch.delenv("FRIGATE_X_PROXY_SECRET", raising=False)
    monkeypatch.delenv("HA_CA_CERTIFICATE", raising=False)
    monkeypatch.delenv("IDP_ISSUER", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_federation_settings_are_optional(ca_cert_pem, frigate_secret, monkeypatch):
    """The pre-federation env set (the shipped k8s manifest) must still validate.

    Federation is opt-in: IDP_ISSUER / SECRET_KEY / PROVIDERS_FILE are absent
    there, and their absence must not break startup.
    """
    from envoy_authz.config import Settings

    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", frigate_secret)
    monkeypatch.setenv("HA_CA_CERTIFICATE", ca_cert_pem)
    for name in ("IDP_ISSUER", "SECRET_KEY", "PROVIDERS_FILE", "OP_KEY_PATH"):
        monkeypatch.delenv(name, raising=False)

    s = Settings(_env_file=None)
    assert s.idp_issuer is None
    assert s.secret_key is None
    assert s.providers_file is None


def test_settings_preserves_env_names_and_defaults(
    ca_cert_pem, frigate_secret, monkeypatch
):
    from envoy_authz.config import Settings

    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", frigate_secret)
    monkeypatch.setenv("HA_CA_CERTIFICATE", ca_cert_pem)
    monkeypatch.setenv("IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.delenv("HA_CRL", raising=False)
    monkeypatch.delenv("GRPC_PORT", raising=False)
    monkeypatch.delenv("HTTP_PORT", raising=False)

    s = Settings()
    assert s.frigate_x_proxy_secret.get_secret_value() == frigate_secret
    assert s.ha_ca_certificate == ca_cert_pem
    assert s.ha_crl is None
    assert s.idp_issuer == "https://idp.example.com"
    assert s.secret_key.get_secret_value() == "test-secret-key"
    assert s.grpc_port == 5000
    assert s.http_port == 5001
    assert s.code_ttl_seconds == 10


def test_secret_fields_do_not_leak_in_repr(ca_cert_pem, frigate_secret, monkeypatch):
    from envoy_authz.config import Settings

    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", frigate_secret)
    monkeypatch.setenv("HA_CA_CERTIFICATE", ca_cert_pem)
    monkeypatch.setenv("IDP_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("SECRET_KEY", "super-secret-value")
    s = Settings()
    rep = repr(s)
    assert "super-secret-value" not in rep
    assert frigate_secret not in rep
