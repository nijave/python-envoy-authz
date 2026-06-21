"""Tests for config loading and CRL helpers."""

from OpenSSL import crypto

from envoy_authz import app


def test_expired_crl_not_loaded(expired_crl_pem, ca_cert_pem):
    store = crypto.X509Store()
    store.add_cert(
        crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem.encode()),
    )
    assert app.configure_crl(store, expired_crl_pem) is False


def test_load_config_reads_env(ca_cert_pem, crl_pem, frigate_secret, monkeypatch):
    monkeypatch.setenv("HA_CA_CERTIFICATE", ca_cert_pem)
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", frigate_secret)
    monkeypatch.setenv("HA_CRL", crl_pem)

    config = app.load_config()

    assert config.frigate_proxy_secret == frigate_secret
    assert config.ha_ca_store is not None


def test_load_config_without_crl(ca_cert_pem, frigate_secret, monkeypatch):
    monkeypatch.setenv("HA_CA_CERTIFICATE", ca_cert_pem)
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", frigate_secret)
    monkeypatch.delenv("HA_CRL", raising=False)

    config = app.load_config()

    assert config.frigate_proxy_secret == frigate_secret
