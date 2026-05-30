"""Sanity test that conftest sets env vars before importing the app."""

import os

from OpenSSL import crypto

from envoy_authz import app


def test_frigate_secret_env_var_is_set(frigate_secret):
    assert os.environ["FRIGATE_X_PROXY_SECRET"] == frigate_secret


def test_app_picks_up_frigate_secret(frigate_secret):
    assert app.FRIGATE_X_PROXY_SECRET == frigate_secret


def test_app_ha_ca_store_is_built():
    # If the env var was set in time, the module-level store exists.
    assert app.HA_CA_STORE is not None


def test_expired_crl_not_loaded(expired_crl_pem):
    store = crypto.X509Store()
    store.add_cert(
        crypto.load_certificate(
            crypto.FILETYPE_PEM,
            os.environ["HA_CA_CERTIFICATE"].encode(),
        )
    )
    assert app._configure_crl(store, expired_crl_pem) is False
