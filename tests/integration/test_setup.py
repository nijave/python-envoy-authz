"""Sanity test that conftest sets env vars before importing the app."""

import os

from envoy_authz import app


def test_frigate_secret_env_var_is_set():
    assert os.environ["FRIGATE_X_PROXY_SECRET"] == "test-frigate-secret-abc123"


def test_app_picks_up_frigate_secret():
    assert app.FRIGATE_X_PROXY_SECRET == "test-frigate-secret-abc123"


def test_app_ha_ca_store_is_built():
    # If the env var was set in time, the module-level store exists.
    assert app.HA_CA_STORE is not None
