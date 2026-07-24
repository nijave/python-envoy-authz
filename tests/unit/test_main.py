"""Lifespan wiring tests for __main__.

Both tests patch out the real gRPC server (no TLS port binding). Test 1 verifies
the gRPC server lifecycle is preserved (start/SERVING on enter,
NOT_SERVING/stop(grace=10) on exit) with a patched load_config. Test 2 exercises
the real load_config path (real CA store) and asserts the federator globals get
wired + torn down.
"""

import asyncio
import datetime
import types
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from grpc_health.v1 import health_pb2

from envoy_authz import __main__ as main_module


def _write_providers(path) -> None:
    path.write_text(
        "providers:\n  vikunja:\n    hosts: ['vikunja.test']\n"
        "    client_id: 'v'\n    client_secret: 's'\n"
        "    redirect_url: 'http://localhost:3456/auth/openid/broker'\n"
        "    api_base: 'http://localhost:3456'\n    provider_key: 'broker'\n"
        "    scope: 'openid profile email'\n"
    )


def _self_signed_ca_pem() -> str:
    """A real self-signed CA PEM so load_config() -> build_store() succeeds."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_lifespan_starts_and_drains_grpc_server(monkeypatch, tmp_path):
    """The gRPC server lifecycle is preserved: start + SERVING on enter,
    NOT_SERVING + stop(grace=10) on exit."""
    providers_path = tmp_path / "providers.yaml"
    _write_providers(providers_path)
    fake_config = types.SimpleNamespace(
        settings=types.SimpleNamespace(
            providers_file=str(providers_path),
            grpc_port=5000,
            federation=lambda: None,  # federation off: gRPC lifecycle only
        )
    )
    fake_server = MagicMock()
    fake_health = MagicMock()

    monkeypatch.setattr(main_module, "load_config", lambda: fake_config)
    monkeypatch.setattr(
        main_module, "build_grpc_server", lambda config: (fake_server, fake_health)
    )

    app = MagicMock()

    async def run():
        async with main_module.lifespan(app):
            fake_server.start.assert_called_once()
            fake_health.set.assert_called_once_with(
                "", health_pb2.HealthCheckResponse.SERVING
            )
            fake_health.set.reset_mock()

    asyncio.run(run())

    fake_health.set.assert_called_once_with(
        "", health_pb2.HealthCheckResponse.NOT_SERVING
    )
    fake_server.stop.assert_called_once_with(grace=10)


def test_lifespan_loads_providers_and_wires_federator(monkeypatch, tmp_path):
    """The lifespan also loads providers, seeds the OP store, and wires the
    federator module globals — then tears them down on shutdown."""
    from envoy_authz import grpc_service

    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", _self_signed_ca_pem())
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("PROVIDERS_FILE", str(tmp_path / "providers.yaml"))
    monkeypatch.setenv("OP_KEY_PATH", str(tmp_path / "op_key.pem"))
    _write_providers(tmp_path / "providers.yaml")

    # Avoid binding a real gRPC port.
    fake_server = MagicMock()
    fake_health = MagicMock()
    monkeypatch.setattr(
        main_module, "build_grpc_server", lambda config: (fake_server, fake_health)
    )

    app = MagicMock()

    async def run():
        async with main_module.lifespan(app):
            assert grpc_service._vikunja is not None
            assert grpc_service._SESSIONS is not None
            fake_server.start.assert_called_once()

    asyncio.run(run())

    # Teardown resets the federator globals + drains the gRPC server.
    assert grpc_service._vikunja is None
    assert grpc_service._SESSIONS is None
    fake_server.stop.assert_called_once_with(grace=10)


def test_lifespan_skips_federation_when_not_configured(monkeypatch, tmp_path):
    """Federation is opt-in. With the pre-federation env set (the shipped k8s
    manifest) startup must succeed and simply not wire the federator, rather
    than failing validation and taking the mTLS + Frigate gate down with it."""
    from envoy_authz import grpc_service

    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", _self_signed_ca_pem())
    for name in ("IDP_ISSUER", "SECRET_KEY", "PROVIDERS_FILE"):
        monkeypatch.delenv(name, raising=False)

    fake_server = MagicMock()
    fake_health = MagicMock()
    monkeypatch.setattr(
        main_module, "build_grpc_server", lambda config: (fake_server, fake_health)
    )

    app = MagicMock()

    async def run():
        async with main_module.lifespan(app):
            assert grpc_service._vikunja is None
            assert grpc_service._SESSIONS is None
            fake_server.start.assert_called_once()

    asyncio.run(run())
    fake_server.stop.assert_called_once_with(grace=10)


def test_failed_grpc_startup_does_not_leak_the_federator_pool(monkeypatch, tmp_path):
    """build_grpc_server runs after init_federator (e.g. missing TLS material),
    so its failure must still release the httpx pool."""
    import pytest

    from envoy_authz import grpc_service

    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", _self_signed_ca_pem())
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("PROVIDERS_FILE", str(tmp_path / "providers.yaml"))
    monkeypatch.setenv("OP_KEY_PATH", str(tmp_path / "op_key.pem"))
    _write_providers(tmp_path / "providers.yaml")

    def _boom(config):
        raise FileNotFoundError("/var/lib/tls/tls.key")

    monkeypatch.setattr(main_module, "build_grpc_server", _boom)

    app = MagicMock()

    async def run():
        async with main_module.lifespan(app):
            pass

    with pytest.raises(FileNotFoundError):
        asyncio.run(run())

    assert grpc_service._vikunja is None
    assert grpc_service._SESSIONS is None
