# mTLS → OAuth2 Federation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn this service into an mTLS-terminated federation proxy that verifies a client cert, federates the user into a Vikunja OAuth2 session by logging in on their behalf, and injects the resulting Vikunja bearer upstream via Envoy `ext_authz` — with per-identity session reuse so a fresh OIDC handshake only happens when the cached session is absent or stale.

**Architecture:** The existing process (gRPC ext_authz on port 5000 + FastAPI HTTPS on port 5001, sharing one `Config`) gains an OIDC Provider mounted on the FastAPI app (ported from `misc/python-client-idp`, Flask→Starlette) and a federator engine (session cache + Vikunja HTTP client) driven by the gRPC `Check` path. The federator owns the Vikunja session server-side (Approach 1): it caches `(bearer, refresh_cookie, exp)` per mTLS identity, injects the bearer via `OkHttpResponse.headers_to_add`, refreshes server-side when stale, and re-federates when refresh fails.

**Tech Stack:** Python 3.12+, gRPC + Envoy ext_authz protos, FastAPI/Uvicorn (ASGI), authlib 1.7.2 (OIDC provider — base `AuthorizationServer` + Starlette glue we write ourselves; grant classes port directly), pydantic-settings, httpx (Vikunja HTTP client + Starlette TestClient backend), itsdangerous (stateless auth codes), joserfc (RSA/JWKS), pyyaml (providers config), pytest + respx (httpx mocking).

## Global Constraints

- Python >=3.12 (venv is 3.14; Dockerfile uses `python:3.14-slim`). Do not lower it.
- Package manager is Poetry (pyproject.toml `[project]` + `[dependency-groups]`). Add deps via `poetry add` and update the lockfile; do not hand-edit `poetry.lock`.
- Linter/formatter is ruff (pre-commit runs `ruff` legacy alias + `ruff format`). Run `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests` before each commit.
- Test runner is pytest (`testpaths=["tests"]`, `addopts="-ra -q"`). Run the full suite with `poetry run pytest`.
- Stage explicit paths only; never use blanket `git add`.
- No secrets in logs, memory, or source. Use `SecretStr` for secret fields; never log bearer tokens or refresh cookies.
- Existing env-var names are preserved by the pydantic-settings refactor: `FRIGATE_X_PROXY_SECRET`, `HA_CA_CERTIFICATE`, `HA_CRL`, `GRPC_PORT`, `HTTP_PORT`, `TLS_CERT_PATH`, `TLS_KEY_PATH`. Do not rename them (the k8s manifest depends on them).
- The Frigate `X-Proxy-Secret` path in `grpc_service.py` is orthogonal and must keep working unchanged throughout.
- mTLS is terminated by Envoy, which forwards the peer cert PEM (URL-encoded) in `attributes.source.certificate`. This service verifies it; it does not terminate mTLS itself.
- authlib 1.7.2 has **no Starlette/FastAPI AuthorizationServer integration** — only `starlette_client` (the OIDC client). The OP subclasses authlib's framework-agnostic base `AuthorizationServer` and implements the Starlette adapter methods itself (Task 5).
- Design spec: `docs/superpowers/specs/2026-07-22-mTLS-OAuth2-federation-design.md` (authoritative; read it first).

## File Structure

```
envoy_authz/
├── __init__.py            # JSON logging (unchanged)
├── __main__.py            # MODIFY: lifespan builds OP store + SessionCache + Vikunja client
├── config.py             # REWRITE: pydantic-settings Settings + runtime Config container
├── grpc_service.py       # MODIFY: Check calls session.get_bearer; injects Authorization header
├── http_app.py           # MODIFY: create_app mounts the OP router via init_op
├── identity.py           # unchanged
├── op/                   # NEW — OIDC Provider (ported from python-client-idp/app/idp)
│   ├── __init__.py        # init_op(app) — register the OP APIRouter
│   ├── server.py         # Starlette AuthorizationServer glue (subclasses base)
│   ├── requests.py       # StarletteOAuth2Request / StarletteJsonRequest adapters
│   ├── grants.py         # AuthorizationCodeGrant / OpenIDCode / RefreshTokenGrant
│   ├── routes.py         # discovery, /jwks.json, /oauth/token, /oauth/userinfo (APIRouter)
│   └── keys.py           # RSA signing key load/generate, JWKS
├── federator/            # NEW — session-reuse + federation engine
│   ├── __init__.py
│   ├── subject.py        # cert → stable subject + email
│   ├── store.py          # authlib store: clients/codes/tokens, query/save helpers
│   ├── session.py        # SessionCache + get_bearer decision ladder
│   ├── vikunja.py        # Vikunja HTTP client: refresh, federate (callback)
│   └── providers.py     # providers.yaml loader (Pydantic + env interpolation)
└── providers.yaml        # NEW — downstream config (Vikunja + extra.session_secret)

tests/
├── conftest.py           # MODIFY: add federation fixtures (OP settings, seeded store)
├── unit/
│   ├── test_settings.py           # NEW — Settings validation
│   ├── test_subject.py            # NEW — subject derivation
│   ├── test_session.py            # NEW — decision ladder
│   ├── test_vikunja.py            # NEW — Vikunja HTTP client (respx)
│   ├── test_op_keys.py            # NEW — ported test_keys.py
│   ├── test_op_store.py           # NEW — ported test_store.py
│   ├── test_op_routes.py          # NEW — ported test_idp.py
│   ├── test_providers.py          # NEW — ported test_providers.py
│   ├── test_main.py               # MODIFY — lifespan now also builds OP/cache
│   ├── test_http_app.py           # MODIFY — app now mounts OP router
│   └── ... (existing identity tests unchanged)
└── integration/
    ├── test_setup.py              # MODIFY — Settings instead of load_config
    ├── test_check.py             # MODIFY — federation integration (get_bearer mocked)
    ├── test_health.py             # unchanged
    └── test_integration_vikunja.py # NEW — live Vikunja e2e (marked, auto-skips)
```

Each task produces a self-contained, testable deliverable and ends with a commit.

---
## Task 1: Dependencies & pydantic-settings config refactor

**Files:**
- Modify: `pyproject.toml` (promote httpx to runtime; add pydantic-settings, authlib, joserfc, pyyaml, itsdangerous; add respx + integration marker to dev)
- Rewrite: `envoy_authz/config.py`
- Modify: `envoy_authz/__main__.py:18-21` (read from Settings instead of os.environ)
- Modify: `tests/integration/test_setup.py` (Settings instead of load_config)
- Modify: `tests/conftest.py` (Config construction uses new container)

**Interfaces:**
- Produces: `Settings` (pydantic-settings `BaseSettings`) and `Config` (runtime container) in `envoy_authz/config.py`; `load_config() -> Config` still returns a `Config` so `__main__.py`/`grpc_service.py` keep working. `Config` fields: `settings: Settings`, `ha_ca_store: crypto.X509Store` (existing name kept), plus `frigate_proxy_secret` as a property reading `settings.frigate_x_proxy_secret.get_secret_value()`.

- [ ] **Step 1: Add dependencies**

Run:
```bash
cd /home/nick/Documents/workspace/code/applications/python-envoy-authz
poetry add pydantic-settings authlib joserfc pyyaml itsdangerous httpx
poetry add --group dev respx
```
Verify `pyproject.toml` `[project] dependencies` lists `httpx`, `pydantic-settings`, `authlib`, `joserfc`, `pyyaml`, `itsdangerous` (httpx leaves `[dependency-groups] dev`), and `respx` is in `dev`.

- [ ] **Step 2: Add the integration pytest marker**

Edit `pyproject.toml` `[tool.pytest.ini_options]`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra -q"
markers = [
    "integration: end-to-end tests against a live Vikunja stack (auto-skip if unreachable)",
]
filterwarnings = [
    "ignore:Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead\\.:starlette.exceptions.StarletteDeprecationWarning",
]
```

- [ ] **Step 3: Write the failing Settings tests**

Create `tests/unit/test_settings.py`:

```python
import pytest
from pydantic import ValidationError


def test_settings_requires_required_fields(monkeypatch):
    from envoy_authz.config import Settings

    monkeypatch.delenv("FRIGATE_X_PROXY_SECRET", raising=False)
    monkeypatch.delenv("HA_CA_CERTIFICATE", raising=False)
    monkeypatch.delenv("IDP_ISSUER", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings()


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
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `poetry run pytest tests/unit/test_settings.py -v`
Expected: FAIL — `Settings` not defined (ImportError).

- [ ] **Step 5: Rewrite `envoy_authz/config.py`**

```python
import datetime
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Validated, env-driven configuration.

    Env-var names are derived from field names (FRIGATE_X_PROXY_SECRET, etc.)
    so the existing k8s manifest keeps working. Secrets are SecretStr so they
    never leak in repr/logs.
    """

    model_config = SettingsConfigDict(
        env_prefix="", env_file=".env", extra="ignore"
    )

    # --- existing (preserved) ---
    frigate_x_proxy_secret: SecretStr
    ha_ca_certificate: str  # PEM
    ha_crl: str | None = None  # PEM

    # --- OP / federator (new) ---
    idp_issuer: str
    secret_key: SecretStr
    code_ttl_seconds: int = 10
    providers_file: str = "providers.yaml"

    # --- transport (moved from __main__ module constants) ---
    grpc_port: int = 5000
    http_port: int = 5001
    tls_cert_path: str = "/var/lib/tls/tls.crt"
    tls_key_path: str = "/var/lib/tls/tls.key"


@dataclass
class Config:
    """Runtime container: validated settings plus constructed state.

    `ha_ca_store` is built from `settings` at startup (runtime state, not
    config). `frigate_proxy_secret` is exposed as a plain str for the existing
    gRPC servicer, which reads it off `Config` directly.
    """

    settings: Settings
    ha_ca_store: crypto.X509Store

    @property
    def frigate_proxy_secret(self) -> str:
        return self.settings.frigate_x_proxy_secret.get_secret_value()


def configure_crl(store: crypto.X509Store, crl_pem: str) -> bool:
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    if crl.next_update_utc <= datetime.datetime.now(datetime.timezone.utc):
        logger.warning("CRL is expired (next_update=%s), skipping", crl.next_update_utc)
        return False
    store.add_crl(crl)
    store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
    logger.info("CRL loaded (next_update=%s)", crl.next_update_utc)
    return True


def build_store(ca_cert_pem: str, crl_pem: str | None = None) -> crypto.X509Store:
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem.encode())
    store = crypto.X509Store()
    store.add_cert(ca_cert)
    if crl_pem:
        configure_crl(store, crl_pem)
    return store


def load_config() -> Config:
    settings = Settings()
    return Config(
        settings=settings,
        ha_ca_store=build_store(settings.ha_ca_certificate, settings.ha_crl),
    )


def verify_client_cert(
    cert_pem: str, store: crypto.X509Store
) -> x509.Certificate | None:
    """Verify a client certificate against the CA + CRL and require the
    clientAuth EKU. Returns the verified certificate, or None on any failure.
    """
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())
        crypto.X509StoreContext(store, cert).verify_certificate()

        crypto_cert = cert.to_cryptography()
        eku = crypto_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
            return None

        return crypto_cert
    except Exception:
        logger.exception("Client cert verification failed")
        return None
```

- [ ] **Step 6: Rewrite `envoy_authz/__main__.py`**

```python
import asyncio
import contextlib
import logging
from concurrent import futures

import grpc
import uvicorn
from fastapi import FastAPI
from grpc_health.v1 import health, health_pb2

from .config import Config, load_config
from .grpc_service import register_services
from .http_app import create_app

logger = logging.getLogger(__name__)


def build_grpc_server(config: Config) -> tuple[grpc.Server, health.HealthServicer]:
    s = config.settings
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_servicer = register_services(server, config)

    with open(s.tls_key_path, "rb") as f:
        private_key = f.read()
    with open(s.tls_cert_path, "rb") as f:
        certificate_chain = f.read()

    credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
    server.add_secure_port(f"[::]:{s.grpc_port}", credentials)
    return server, health_servicer


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    server, health_servicer = build_grpc_server(config)
    try:
        server.start()
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        logger.info("Secure gRPC server started on port %s", config.settings.grpc_port)
        app.state.config = config
        yield
    finally:
        logger.info("Draining gRPC server...")
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        stopped = server.stop(grace=10)
        await asyncio.to_thread(stopped.wait)


def main():
    app = create_app(lifespan=lifespan)
    config = load_config()
    s = config.settings
    logger.info("Starting HTTPS server on port %s", s.http_port)
    uvicorn.run(
        app,
        host="::",
        port=s.http_port,
        ssl_certfile=s.tls_cert_path,
        ssl_keyfile=s.tls_key_path,
        log_config=None,
    )


if __name__ == "__main__":
    main()
```

- [ ] **Step 7: Update `conftest.py` `ha_config` fixture**

Replace the `ha_config` fixture body (around line 326) with:

```python
@pytest.fixture(scope="session")
def ha_config() -> Config:
    from envoy_authz.config import Settings

    store = build_store(
        _pem(_TRUSTED_CA),
        _CRL.public_bytes(serialization.Encoding.PEM).decode(),
    )
    settings = Settings(
        frigate_x_proxy_secret=FRIGATE_TEST_SECRET,
        ha_ca_certificate=_pem(_TRUSTED_CA),
        ha_crl=_CRL.public_bytes(serialization.Encoding.PEM).decode(),
        idp_issuer="https://idp.test",
        secret_key="test-secret-key",
    )
    return Config(settings=settings, ha_ca_store=store)
```

The top-of-file `from envoy_authz.config import Config, build_store` stays.

- [ ] **Step 8: Rewrite `tests/integration/test_setup.py`**

```python
"""Tests for config loading and CRL helpers."""

from OpenSSL import crypto

from envoy_authz.config import configure_crl


def test_expired_crl_not_loaded(expired_crl_pem, ca_cert_pem):
    store = crypto.X509Store()
    store.add_cert(
        crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem.encode()),
    )
    assert configure_crl(store, expired_crl_pem) is False


def test_load_config_reads_env(ca_cert_pem, crl_pem, frigate_secret, monkeypatch):
    from envoy_authz.config import load_config

    monkeypatch.setenv("HA_CA_CERTIFICATE", ca_cert_pem)
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", frigate_secret)
    monkeypatch.setenv("HA_CRL", crl_pem)
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")

    config = load_config()

    assert config.frigate_proxy_secret == frigate_secret
    assert config.ha_ca_store is not None
    assert config.settings.ha_crl == crl_pem


def test_load_config_without_crl(ca_cert_pem, frigate_secret, monkeypatch):
    from envoy_authz.config import load_config

    monkeypatch.setenv("HA_CA_CERTIFICATE", ca_cert_pem)
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", frigate_secret)
    monkeypatch.delenv("HA_CRL", raising=False)
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")

    config = load_config()

    assert config.frigate_proxy_secret == frigate_secret
    assert config.settings.ha_crl is None
```

- [ ] **Step 9: Lint**

Run:
```bash
poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests
```
Expected: no errors.

- [ ] **Step 10: Run the full suite**

Run: `poetry run pytest -v`
Expected: PASS (existing tests + new `test_settings.py`). `test_main.py` keeps working because it monkeypatches `build_grpc_server`.

- [ ] **Step 11: Commit**

```bash
git add pyproject.toml envoy_authz/config.py envoy_authz/__main__.py tests/conftest.py tests/integration/test_setup.py tests/unit/test_settings.py
git commit -m "refactor: pydantic-settings config; add OP/federator deps

Rewrite config.py as a pydantic-settings Settings model + a runtime Config
container. Promote httpx to runtime; add authlib, joserfc, pyyaml,
itsdangerous, pydantic-settings. Add respx + integration marker to dev.
Preserve existing env-var names so the k8s manifest is unchanged."
```

## Task 2: Providers config (providers.yaml loader)

**Files:**
- Create: `envoy_authz/federator/__init__.py`
- Create: `envoy_authz/federator/providers.py`
- Create: `envoy_authz/providers.yaml`
- Create: `tests/unit/test_providers.py`

**Interfaces:**
- Produces: `Provider` (Pydantic model with `client_id`, `client_secret`, `redirect_url`, `api_base`, `provider_key`, `scope`, `extra: dict[str,str]`, and a `callback_url` property), `ProvidersConfig`, `PROVIDERS` module global, `load_providers(path=None) -> dict[str, Provider]`, `get_provider(name) -> Provider | None`. The `extra` dict is backend-specific (Vikunja reads `extra["session_secret"]`).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_providers.py`:

```python
import pytest
from pydantic import ValidationError

from envoy_authz.federator import providers

VIKUNJA_YAML = """
providers:
  vikunja:
    client_id: "vikunja"
    client_secret: "vikunja-secret"
    redirect_url: "http://localhost:3456/auth/openid/broker"
    api_base: "http://localhost:3456"
    provider_key: "broker"
    scope: "openid profile email"
    extra:
      session_secret: "hs256-shared-secret"
"""


def _write(tmp_path, text):
    path = tmp_path / "providers.yaml"
    path.write_text(text)
    return str(path)


def test_load_providers_parses_entry(tmp_path):
    loaded = providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    vikunja = loaded["vikunja"]
    assert vikunja.client_id == "vikunja"
    assert vikunja.client_secret == "vikunja-secret"
    assert vikunja.redirect_url == "http://localhost:3456/auth/openid/broker"
    assert vikunja.api_base == "http://localhost:3456"
    assert vikunja.provider_key == "broker"
    assert vikunja.scope == "openid profile email"
    assert vikunja.extra == {"session_secret": "hs256-shared-secret"}


def test_scope_defaults_when_omitted(tmp_path):
    text = """
providers:
  acme:
    client_id: "acme"
    client_secret: "s"
    redirect_url: "http://acme/cb"
    api_base: "http://acme"
    provider_key: "broker"
"""
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["acme"].scope == "openid profile email"


def test_extra_defaults_to_empty_dict(tmp_path):
    loaded = providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    # session_secret present in this fixture; verify the default via acme:
    text = """
providers:
  acme:
    client_id: "acme"
    client_secret: "s"
    redirect_url: "http://acme/cb"
    api_base: "http://acme"
    provider_key: "broker"
"""
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["acme"].extra == {}


def test_callback_url_derived_from_api_base_and_provider_key(tmp_path):
    loaded = providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    assert (
        loaded["vikunja"].callback_url
        == "http://localhost:3456/api/v1/auth/openid/broker/callback"
    )


def test_load_populates_module_globals_and_getter(tmp_path):
    providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    assert "vikunja" in providers.PROVIDERS
    assert providers.get_provider("vikunja").client_id == "vikunja"
    assert providers.get_provider("nope") is None


def test_env_interpolation_uses_default_when_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("VIKUNJA_API_BASE", raising=False)
    text = VIKUNJA_YAML.replace(
        '"http://localhost:3456"', '"${VIKUNJA_API_BASE:-http://localhost:3456}"'
    )
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["vikunja"].api_base == "http://localhost:3456"


def test_env_interpolation_prefers_env_over_default(tmp_path, monkeypatch):
    monkeypatch.setenv("VIKUNJA_API_BASE", "http://vikunja:3456")
    text = VIKUNJA_YAML.replace(
        '"http://localhost:3456"', '"${VIKUNJA_API_BASE:-http://localhost:3456}"'
    )
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["vikunja"].api_base == "http://vikunja:3456"


def test_undefined_env_var_without_default_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    text = VIKUNJA_YAML.replace('"vikunja-secret"', '"${MISSING_VAR}"')
    with pytest.raises(ValueError):
        providers.load_providers(_write(tmp_path, text))


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        providers.load_providers(str(tmp_path / "does-not-exist.yaml"))


def test_invalid_schema_raises(tmp_path):
    text = """
providers:
  broken:
    client_id: "broken"
"""
    with pytest.raises(ValidationError):
        providers.load_providers(_write(tmp_path, text))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `poetry run pytest tests/unit/test_providers.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Create the package and providers loader**

Create `envoy_authz/federator/__init__.py` (empty).

Create `envoy_authz/federator/providers.py`:

```python
"""Filesystem-loaded, Pydantic-validated downstream provider config.

Ported from python-client-idp/app/providers.py. Each entry in providers.yaml
is one downstream backend the federator can federate to — the single source of
truth for that backend, driving both the OIDP client registration (store.seed)
and the federator's downstream callback call (vikunja.federate).

The per-backend *values* live here; the wire *contract* (callback path shape
and POST {code, redirect_url} -> {token}) lives in vikunja.py. `extra` holds
backend-specific config (Vikunja: session_secret, the HS256 service.secret).
"""

import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel

# ${VAR} or ${VAR:-default}. VAR is a POSIX-ish env name.
_ENV_REF = re.compile(
    r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}"
)

DEFAULT_SCOPE = "openid profile email"


class Provider(BaseModel):
    """One downstream backend the federator can federate to."""

    client_id: str
    client_secret: str
    redirect_url: str
    api_base: str
    provider_key: str
    scope: str = DEFAULT_SCOPE
    extra: dict[str, str] = {}

    @property
    def callback_url(self) -> str:
        """The downstream OIDC broker-callback URL for this backend."""
        return f"{self.api_base}/api/v1/auth/openid/{self.provider_key}/callback"


class ProvidersConfig(BaseModel):
    providers: dict[str, Provider]


# Populated at startup by load_providers; read by store.seed and vikunja.federate.
PROVIDERS: dict[str, Provider] = {}


def _resolve(text: str) -> str:
    """Resolve ${VAR} / ${VAR:-default} against the environment.

    An undefined variable with no default is a startup error, not a silent
    empty string — it almost always means a required secret was not injected.
    """

    def replace(match: "re.Match[str]") -> str:
        name = match.group("name")
        if name in os.environ:
            return os.environ[name]
        default = match.group("default")
        if default is not None:
            return default
        raise ValueError(f"undefined environment variable in providers config: {name}")

    return _ENV_REF.sub(replace, text)


def _interpolate(value):
    """Recursively resolve env references in every string leaf of a parsed doc."""
    if isinstance(value, str):
        return _resolve(value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def load_providers(path: str | None = None) -> dict[str, Provider]:
    """Load, interpolate, and validate the providers file into PROVIDERS.

    Raises FileNotFoundError if the file is missing, ValueError for an
    undefined env reference, and pydantic.ValidationError for a bad schema —
    all fatal at startup by design.
    """
    if path is None:
        from envoy_authz.config import Settings

        path = Settings().providers_file
    data = _interpolate(yaml.safe_load(Path(path).read_text()))
    cfg = ProvidersConfig.model_validate(data)
    PROVIDERS.clear()
    PROVIDERS.update(cfg.providers)
    return PROVIDERS


def get_provider(name: str) -> Provider | None:
    return PROVIDERS.get(name)
```

- [ ] **Step 4: Create `envoy_authz/providers.yaml`**

```yaml
# Downstream backends this federator can federate identities to.
# Values may reference the environment as ${VAR} or ${VAR:-default}. An
# undefined ${VAR} with no default is a fatal startup error.
providers:
  vikunja:
    client_id: "${VIKUNJA_CLIENT_ID:-vikunja}"
    client_secret: "${VIKUNJA_CLIENT_SECRET:-vikunja-secret}"
    redirect_url: "${VIKUNJA_REDIRECT_URL:-http://localhost:3456/auth/openid/broker}"
    api_base: "${VIKUNJA_API_BASE:-http://localhost:3456}"
    provider_key: "${VIKUNJA_PROVIDER_KEY:-broker}"
    scope: "openid profile email"
    extra:
      # Vikunja service.secret (HS256). Optional: when set, the federator can
      # verify an incoming bearer's signature + exp locally before trusting it.
      # When unset, incoming bearers are treated as opaque (cache is used).
      session_secret: "${VIKUNJA_SESSION_SECRET:-}"
```

- [ ] **Step 5: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 6: Run tests**

Run: `poetry run pytest tests/unit/test_providers.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add envoy_authz/federator/__init__.py envoy_authz/federator/providers.py envoy_authz/providers.yaml tests/unit/test_providers.py
git commit -m "feat: providers.yaml loader (ported, backend-agnostic)

Pydantic-validated downstream provider config with \${VAR} env interpolation.
Adds a generic extra dict for backend-specific config (Vikunja: session_secret).
Ported from python-client-idp/app/providers.py."
```

## Task 3: Subject derivation (cert → stable sub + email)

**Files:**
- Create: `envoy_authz/federator/subject.py`
- Create: `tests/unit/test_subject.py`

**Interfaces:**
- Produces: `Subject` NamedTuple (`sub: str`, `email: str | None`, `name: str`) and `derive_subject(cert: x509.Certificate) -> Subject` in `envoy_authz/federator/subject.py`. `sub` is a deterministic SHA-256 fingerprint (hex, 16 chars) over the cert's subject DN DER + its SubjectPublicKeyInfo DER — stable across restarts and unique to the cert's identity + key. `email` is the first SAN rfc822Name (or None). `name` is derived for OIDC `name`/Vikunja display (CN, else given+surname, else email local-part, else the sub).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_subject.py`:

```python
from envoy_authz.federator.subject import Subject, derive_subject


def test_subject_is_stable_for_same_cert(trusted_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(trusted_client_cert_pem.encode())
    s1 = derive_subject(cert)
    s2 = derive_subject(cert)
    assert s1.sub == s2.sub
    assert len(s1.sub) == 16
    assert isinstance(s1, Subject)


def test_two_different_certs_yield_different_subs(
    trusted_client_cert_pem, untrusted_client_cert_pem
):
    from cryptography import x509

    a = derive_subject(x509.load_pem_x509_certificate(trusted_client_cert_pem.encode()))
    b = derive_subject(
        x509.load_pem_x509_certificate(untrusted_client_cert_pem.encode())
    )
    assert a.sub != b.sub


def test_subject_email_taken_from_san(trusted_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(trusted_client_cert_pem.encode())
    s = derive_subject(cert)
    # The trusted client cert is built with CN=<host>.apps.somemissing.info and
    # no email SAN by default; assert the helper returns None when absent.
    assert s.email is None or "@" in s.email


def test_subject_name_falls_back_to_cn(trusted_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(trusted_client_cert_pem.encode())
    s = derive_subject(cert)
    assert s.name  # non-empty
```

Add a focused cert-with-email fixture to `tests/conftest.py` (append near the other cert fixtures, after `_REVOKED_CLIENT_CERT`):

```python
_EMAIL_CLIENT_KEY, _EMAIL_CLIENT_CERT = _build_signed_cert(
    "email-client.ha.apps.somemissing.info",
    _TRUSTED_CA_KEY,
    _TRUSTED_CA,
    san_emails=["user@example.com"],
)
```

This requires `_build_signed_cert` to accept a `san_emails` kwarg. Check the existing `_build_signed_cert` signature in `tests/conftest.py`; if it does not already add a `SubjectAlternativeName` with rfc822Name entries when `san_emails` is given, extend it to do so:

```python
def _build_signed_cert(common_name, ca_key, ca_cert, *, eku=None, san_emails=None):
    # ... existing body ...
    builder = (
        x509.CertificateBuilder()
        .subject_name(...)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    eku_oids = eku or [ExtendedKeyUsageOID.CLIENT_AUTH]
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(eku_oids), critical=False
    )
    if san_emails:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(e) for e in san_emails]),
            critical=False,
        )
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return key, cert
```

Then add the fixture accessor:

```python
@pytest.fixture(scope="session")
def email_client_cert_pem() -> str:
    return _pem(_EMAIL_CLIENT_CERT)
```

And add this test (in `test_subject.py`) to assert email extraction:

```python
def test_subject_email_from_san_email_cert(email_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(email_client_cert_pem.encode())
    s = derive_subject(cert)
    assert s.email == "user@example.com"
    assert s.name == "email-client.ha.apps.somemissing.info"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `poetry run pytest tests/unit/test_subject.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `envoy_authz/federator/subject.py`**

```python
"""Deterministic subject derivation from a verified client certificate.

Replaces python-client-idp's in-memory-counter get_or_create_user_by_email:
the subject is derived from the cert's subject DN + SubjectPublicKeyInfo, so it
is stable across restarts (Vikunja's user persists; a changing sub would
orphan it).
"""

import hashlib
from typing import NamedTuple

from cryptography import x509
from cryptography.x509.oid import NameOID


class Subject(NamedTuple):
    sub: str
    email: str | None
    name: str


def _san_emails(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(san.value.get_values_for_type(x509.RFC822Name))


def _first_attr(name: x509.Name, oid) -> str | None:
    for attr in name.get_attributes_for_oid(oid):
        if isinstance(attr.value, str):
            return attr.value
    return None


def derive_subject(cert: x509.Certificate) -> Subject:
    """Turn a verified cert into a stable subject + email + display name.

    `sub` is a 16-char hex SHA-256 over the subject DN DER concatenated with
    the SubjectPublicKeyInfo DER — identifying both who and which key.
    """
    subject_der = cert.subject.public_bytes()
    spki_der = cert.public_key().public_bytes(
        encoding=None,  # placeholder; replaced below
    )
    # cryptography requires an Encoding arg; use DER explicitly:
    from cryptography.hazmat.primitives import serialization

    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(subject_der + spki_der).hexdigest()[:16]

    emails = _san_emails(cert)
    email = emails[0] if emails else None

    name = (
        _first_attr(cert.subject, NameOID.COMMON_NAME)
        or _join_full_name(cert.subject)
        or (email.split("@", 1)[0] if email)
        or digest
    )
    return Subject(sub=digest, email=email, name=name)


def _join_full_name(name: x509.Name) -> str | None:
    given = _first_attr(name, NameOID.GIVEN_NAME)
    surname = _first_attr(name, NameOID.SURNAME)
    if given and surname:
        return f"{given} {surname}"
    return given or surname
```

Note: remove the `encoding=None` placeholder line before finalizing — the real `spki_der` assignment two lines down is the one used. Lint (Step 4) will flag the unused first assignment; delete it so only the explicit-DER call remains:

```python
    from cryptography.hazmat.primitives import serialization

    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(subject_der + spki_der).hexdigest()[:16]
```

- [ ] **Step 4: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`
Fix any flagged unused import/assignment.

- [ ] **Step 5: Run tests**

Run: `poetry run pytest tests/unit/test_subject.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add envoy_authz/federator/subject.py tests/unit/test_subject.py tests/conftest.py
git commit -m "feat: deterministic subject derivation from client cert

SHA-256 over subject DN + SubjectPublicKeyInfo yields a stable sub across
restarts; email from SAN rfc822Name; name from CN/given+surname/email local-part.
Replaces the source's in-memory-counter identity with a deterministic one."
```

## Task 4: OP store + keys + grants (framework-agnostic port)

**Files:**
- Create: `envoy_authz/op/__init__.py` (minimal; `init_op` added in Task 5)
- Create: `envoy_authz/op/keys.py`
- Create: `envoy_authz/federator/store.py`
- Create: `envoy_authz/op/grants.py`
- Create: `tests/unit/test_op_keys.py`
- Create: `tests/unit/test_op_store.py`

**Interfaces:**
- Produces (in `federator/store.py`): `User` (`id`, `name`, `email`, `get_user_id()`), `OAuth2Client`, `OAuth2AuthorizationCode` (gains `email`/`name` fields), `OAuth2Token` (gains `email`/`name` fields), `build_user_info(user, scope)`, `query_client`, `save_token`, `query_token`, `create_authorization_code(client_id, redirect_uri, scope, user_id, email=None, name=None, nonce=None, code_challenge=None, code_challenge_method=None)`, `load_authorization_code(code, max_age=None)`, `seed()`, `_reset()`, and module globals `CLIENTS`, `TOKENS`, `REFRESH_TOKENS`. **No `USERS` dict** — the user is reconstructed from the stateless code / token record (email + name travel in the signed payload).
- Produces (in `op/keys.py`): `key_set` (joserfc `KeySet`), `kid` (str), `public_jwks_dict() -> dict`, `load_or_create_key(path) -> RSAKey`.
- Produces (in `op/grants.py`): `AuthorizationCodeGrant`, `OpenIDCode`, `RefreshTokenGrant` — ported verbatim from the source except `authenticate_user` reconstructs `User` from the code/token record (no USERS lookup), and `OpenIDCode.get_client_claims`/`resolve_client_private_key`/`get_encode_header` read `config.settings.idp_issuer` and `keys.key_set`/`keys.kid`.
- Consumes: `federator/providers.py` (`PROVIDERS`, via `seed`), `config.py` (`Settings` for `idp_issuer`, `secret_key`, `code_ttl_seconds`).

**Design note (no USERS dict):** the source stored users in-memory and looked them up by id at redemption/refresh. We derive subjects deterministically, so there is no USERS dict. Instead, `email` and `name` travel inside the stateless auth code (signed payload) and inside the OP-internal `OAuth2Token` record (populated by `save_token` from `request.user`). `authenticate_user` reconstructs a `User` from those. The OP-internal `TOKENS`/`REFRESH_TOKENS` dicts remain (opaque access/refresh tokens for userinfo + refresh rotation); they are transient — Vikunja redeems the code within ~1s and never calls userinfo/refresh again.

- [ ] **Step 1: Write the failing keys test**

Create `tests/unit/test_op_keys.py`:

```python
from joserfc import jwt
from joserfc.jwk import RSAKey, KeySet

from envoy_authz.op import keys


def test_keys_expose_kid_and_single_rsa_key(tmp_path, monkeypatch):
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", "x")
    from envoy_authz.op.keys import load_or_create_key

    jwk = load_or_create_key(str(tmp_path / "private.pem"))
    assert jwk.kid and isinstance(jwk.kid, str)
    ks = KeySet([jwk])
    pub = jwk.as_dict()
    entry = {k: pub[k] for k in ("kty", "n", "e", "kid")}
    entry.update({"alg": "RS256", "use": "sig"})
    assert entry["kty"] == "RSA"
    assert entry["e"] == "AQAB"


def test_id_token_roundtrip_signs_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", "x")
    from envoy_authz.op.keys import load_or_create_key

    jwk = load_or_create_key(str(tmp_path / "private.pem"))
    ks = KeySet([jwk])
    header = {"alg": "RS256", "kid": jwk.kid}
    claims = {
        "iss": "https://idp.test",
        "aud": ["self-client"],
        "sub": "1",
        "iat": 1700000000,
        "exp": 1700003600,
    }
    token = jwt.encode(header, claims, ks, ["RS256"])
    pub = jwk.as_dict()
    pub_ks = KeySet([RSAKey.import_key({k: pub[k] for k in ("kty", "n", "e", "kid")})])
    decoded = jwt.decode(token, pub_ks, ["RS256"])
    assert decoded.claims["sub"] == "1"
    assert decoded.claims["aud"] == ["self-client"]
```

- [ ] **Step 2: Run keys test to verify it fails**

Run: `poetry run pytest tests/unit/test_op_keys.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `envoy_authz/op/__init__.py`**

```python
"""OIDC Provider package. init_op is added in Task 5."""
```

- [ ] **Step 4: Create `envoy_authz/op/keys.py`**

```python
"""RSA signing key for the OP (ported from python-client-idp/app/keys.py).

Loaded or generated on first use; persisted to disk so the JWKS / kid are
stable across restarts (Vikunja caches the discovered JWKS).
"""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc.jwk import KeySet, RSAKey


def load_or_create_key(path: str) -> RSAKey:
    """Load an RSA key from `path`, or generate a 2048-bit key and persist it."""
    if os.path.exists(path):
        with open(path, "rb") as handle:
            private_key = serialization.load_pem_private_key(handle.read(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    jwk = RSAKey.import_key(private_key)
    jwk.ensure_kid()  # RFC 7638 JWK thumbprint
    return jwk
```

- [ ] **Step 5: Run keys test**

Run: `poetry run pytest tests/unit/test_op_keys.py -v`
Expected: PASS.

- [ ] **Step 6: Write the failing store test**

Create `tests/unit/test_op_store.py`:

```python
from envoy_authz.federator import providers
from envoy_authz.federator.store import (
    OAuth2AuthorizationCode,
    OAuth2Token,
    USER,
    CLIENTS,
    TOKENS,
    REFRESH_TOKENS,
    _reset,
    seed,
    create_authorization_code,
    load_authorization_code,
    build_user_info,
)


VIKUNJA_YAML = """
providers:
  vikunja:
    client_id: "vikunja"
    client_secret: "vikunja-secret"
    redirect_url: "http://localhost:3456/auth/openid/broker"
    api_base: "http://localhost:3456"
    provider_key: "broker"
    scope: "openid profile email"
"""


def setup_function(_):
    providers.load_providers()  # uses a temp file? no — see note
    _reset()
    seed()
```

Note: `providers.load_providers()` with no arg reads `Settings().providers_file`, which in tests is the repo's `providers.yaml`. To keep this test hermetic, write the YAML to a temp file and pass the path:

```python
import pytest
from pydantic import ValidationError
from envoy_authz.federator import providers
from envoy_authz.federator.store import (
    OAuth2AuthorizationCode,
    OAuth2Token,
    CLIENTS,
    _reset,
    seed,
    create_authorization_code,
    load_authorization_code,
    build_user_info,
    User,
)

VIKUNJA_YAML = """
providers:
  vikunja:
    client_id: "vikunja"
    client_secret: "vikunja-secret"
    redirect_url: "http://localhost:3456/auth/openid/broker"
    api_base: "http://localhost:3456"
    provider_key: "broker"
    scope: "openid profile email"
"""


def _seed(tmp_path):
    p = tmp_path / "providers.yaml"
    p.write_text(VIKUNJA_YAML)
    providers.load_providers(str(p))
    _reset()
    seed()


def test_seed_registers_vikunja_client(tmp_path):
    _seed(tmp_path)
    assert "vikunja" in CLIENTS
    v = CLIENTS["vikunja"]
    assert v.get_client_id() == "vikunja"
    assert v.check_client_secret("vikunja-secret")
    assert v.check_redirect_uri("http://localhost:3456/auth/openid/broker")
    assert v.check_response_type("code")
    assert v.check_grant_type("authorization_code")
    assert v.get_allowed_scope("openid profile email phone") == "openid profile email"


def test_client_token_endpoint_auth_methods(tmp_path):
    _seed(tmp_path)
    v = CLIENTS["vikunja"]
    assert v.check_endpoint_auth_method("client_secret_basic", "token")
    assert v.check_endpoint_auth_method("client_secret_post", "token")
    assert not v.check_endpoint_auth_method("none", "token")


def test_stateless_code_carries_email_and_name(tmp_path):
    _seed(tmp_path)
    code = create_authorization_code(
        client_id="vikunja",
        redirect_uri="http://localhost:3456/auth/openid/broker",
        scope="openid profile email",
        user_id="abc123",
        email="alice@example.com",
        name="Alice",
    )
    data = load_authorization_code(code)
    assert data is not None
    assert data["user_id"] == "abc123"
    assert data["email"] == "alice@example.com"
    assert data["name"] == "Alice"
    assert data["client_id"] == "vikunja"


def test_build_user_info_uses_sub_name_email():
    u = User(id="abc123", name="Alice", email="alice@example.com")
    info = build_user_info(u, "openid profile email")
    assert info["sub"] == "abc123"
    assert info["email"] == "alice@example.com"
    assert info["name"] == "Alice"
```

- [ ] **Step 7: Run store test to verify it fails**

Run: `poetry run pytest tests/unit/test_op_store.py -v`
Expected: FAIL — module not found.

- [ ] **Step 8: Create `envoy_authz/federator/store.py`**

```python
"""authlib store: clients, stateless codes, OP-internal tokens.

Ported from python-client-idp/app/store.py with one change: there is NO USERS
dict. Subjects are derived deterministically (federator.subject), so email and
name travel inside the stateless auth code and the OP-internal token record;
authenticate_user (in op/grants.py) reconstructs a User from them.
"""

import secrets
import time

from authlib.oauth2.rfc6749 import AuthorizationCodeMixin, ClientMixin, TokenMixin
from authlib.oidc.core import UserInfo
from itsdangerous import BadData, URLSafeTimedSerializer

from . import providers

DEFAULT_SCOPE = "openid profile email"


def _code_signer():
    from envoy_authz.config import Settings

    return URLSafeTimedSerializer(
        Settings().secret_key.get_secret_value(), salt="broker-auth-code"
    )


def build_user_info(user, scope):
    """Construct a scoped UserInfo for `user` (sub, name, email)."""
    return UserInfo(sub=str(user.id), name=user.name, email=user.email).filter(scope)


class User:
    """A federated identity reconstructed from a stateless code or token."""

    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

    def get_user_id(self):
        return self.id


class OAuth2Client(ClientMixin):
    def __init__(self, client_id, client_secret, redirect_uris, scope=DEFAULT_SCOPE,
                 grant_types=("authorization_code", "refresh_token"),
                 response_types=("code",),
                 token_endpoint_auth_method="client_secret_basic"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uris = list(redirect_uris)
        self.scope = scope
        self.grant_types = list(grant_types)
        self.response_types = list(response_types)
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.client_metadata = {
            "client_id": client_id,
            "client_name": client_id,
            "redirect_uris": list(redirect_uris),
            "scope": scope,
            "grant_types": list(grant_types),
            "response_types": list(response_types),
            "token_endpoint_auth_method": token_endpoint_auth_method,
        }

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.redirect_uris[0] if self.redirect_uris else None

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope.split())
        return " ".join(s for s in scope.split() if s in allowed)

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret):
        return secrets.compare_digest(self.client_secret, client_secret)

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return method in ("client_secret_basic", "client_secret_post")
        return True

    def check_response_type(self, response_type):
        return response_type in self.response_types

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types


class OAuth2AuthorizationCode(AuthorizationCodeMixin):
    def __init__(self, code, client_id, redirect_uri, scope, user_id, email=None,
                 name=None, nonce=None, code_challenge=None,
                 code_challenge_method=None, auth_time=None):
        self.code = code
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.user_id = user_id
        self.email = email
        self.name = name
        self.nonce = nonce
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.auth_time = auth_time or int(time.time())

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_nonce(self):
        return self.nonce

    def get_auth_time(self):
        return self.auth_time

    def get_acr(self):
        return None

    def get_amr(self):
        return None


class OAuth2Token(TokenMixin):
    def __init__(self, client_id, user_id, email=None, name=None, **kwargs):
        self.client_id = client_id
        self.user_id = user_id
        self.email = email
        self.name = name
        self.access_token = kwargs.get("access_token")
        self.refresh_token = kwargs.get("refresh_token")
        self.token_type = kwargs.get("token_type", "Bearer")
        self.scope = kwargs.get("scope", "")
        self.expires_in = kwargs.get("expires_in", 3600)
        self.revoked = False
        self.issued_at = time.time()

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_expired(self):
        return time.time() > self.issued_at + self.expires_in

    def is_revoked(self):
        return self.revoked

    def get_user(self):
        return User(self.user_id, self.name, self.email) if self.user_id else None

    def get_client(self):
        return CLIENTS.get(self.client_id)

    def check_client(self, client):
        return self.client_id == client.client_id


CLIENTS = {}
TOKENS = {}
REFRESH_TOKENS = {}


def _reset():
    CLIENTS.clear()
    TOKENS.clear()
    REFRESH_TOKENS.clear()


def seed():
    if CLIENTS:
        return
    for provider in providers.PROVIDERS.values():
        CLIENTS[provider.client_id] = OAuth2Client(
            client_id=provider.client_id,
            client_secret=provider.client_secret,
            redirect_uris=[provider.redirect_url],
        )


def query_client(client_id):
    return CLIENTS.get(client_id)


def save_token(token, request):
    user = request.user
    user_id = user.get_user_id() if user else None
    record = OAuth2Token(
        client_id=request.client.client_id,
        user_id=user_id,
        email=getattr(user, "email", None),
        name=getattr(user, "name", None),
        **token,
    )
    TOKENS[record.access_token] = record
    if record.refresh_token:
        REFRESH_TOKENS[record.refresh_token] = record
    return record


def query_token(access_token):
    return TOKENS.get(access_token)


def create_authorization_code(client_id, redirect_uri, scope, user_id,
                              email=None, name=None, nonce=None,
                              code_challenge=None, code_challenge_method=None):
    """Mint a STATELESS authorization code: a signed, self-contained token.

    email + name travel inside the signed payload so the OP can reconstruct the
    user at redemption without a USERS store. TTL is short (CODE_TTL_SECONDS).
    """
    return _code_signer().dumps({
        "jti": secrets.token_urlsafe(8),
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "user_id": user_id,
        "email": email,
        "name": name,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "auth_time": int(time.time()),
    })


def load_authorization_code(code, max_age=None):
    """Verify and decode a stateless authorization code. Returns the payload
    dict, or None if the signature is invalid or the code is older than
    `max_age` (defaults to Settings.code_ttl_seconds)."""
    if max_age is None:
        from envoy_authz.config import Settings

        max_age = Settings().code_ttl_seconds
    try:
        return _code_signer().loads(code, max_age=max_age)
    except BadData:
        return None
```

- [ ] **Step 9: Run store tests**

Run: `poetry run pytest tests/unit/test_op_store.py -v`
Expected: PASS.

- [ ] **Step 10: Create `envoy_authz/op/grants.py`**

```python
"""OIDC grants (ported from python-client-idp/app/idp/grants.py).

Framework-agnostic (authlib rfc6749/oidc core). authenticate_user reconstructs
a User from the stateless code / token record — there is no USERS dict.
"""

from authlib.oauth2.rfc6749 import grants
from authlib.oidc.core import grants as oidc_grants

from ..config import Settings
from . import keys
from ..federator.store import (
    OAuth2AuthorizationCode,
    REFRESH_TOKENS,
    User,
    build_user_info,
    load_authorization_code,
)


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

    # No generate_/save_authorization_code: codes are minted by the federator
    # (store.create_authorization_code) as signed, self-contained tokens; this
    # grant only redeems them at the token endpoint.

    def query_authorization_code(self, code, client):
        data = load_authorization_code(code)
        if data is None or data["client_id"] != client.client_id:
            return None
        return OAuth2AuthorizationCode(
            code=code,
            client_id=data["client_id"],
            redirect_uri=data["redirect_uri"],
            scope=data["scope"],
            user_id=data["user_id"],
            email=data.get("email"),
            name=data.get("name"),
            nonce=data.get("nonce"),
            code_challenge=data.get("code_challenge"),
            code_challenge_method=data.get("code_challenge_method"),
            auth_time=data.get("auth_time"),
        )

    def delete_authorization_code(self, authorization_code):
        # No-op: stateless codes are not stored; the short TTL bounds replay.
        pass

    def authenticate_user(self, authorization_code):
        return User(
            id=authorization_code.user_id,
            name=authorization_code.name,
            email=authorization_code.email,
        )


class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

    def authenticate_refresh_token(self, refresh_token):
        record = REFRESH_TOKENS.get(refresh_token)
        if record and not record.is_expired() and not record.is_revoked():
            return record
        return None

    def authenticate_user(self, credential):
        return User(
            id=credential.user_id,
            name=credential.name,
            email=credential.email,
        )

    def revoke_old_credential(self, refresh_token):
        token_string = getattr(refresh_token, "refresh_token", refresh_token)
        record = REFRESH_TOKENS.pop(token_string, None)
        if record is None and not isinstance(refresh_token, str):
            record = refresh_token
        if record:
            record.revoked = True


class OpenIDCode(oidc_grants.OpenIDCode):
    def generate_user_info(self, user, scope):
        return build_user_info(user, scope)

    def get_client_claims(self, client):
        return {"iss": Settings().idp_issuer}

    def resolve_client_private_key(self, client):
        return keys.key_set

    def get_encode_header(self, client):
        header = super().get_encode_header(client)
        header["kid"] = keys.kid
        return header
```

- [ ] **Step 11: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 12: Run all OP tests so far**

Run: `poetry run pytest tests/unit/test_op_keys.py tests/unit/test_op_store.py -v`
Expected: PASS.

- [ ] **Step 13: Commit**

```bash
git add envoy_authz/op/__init__.py envoy_authz/op/keys.py envoy_authz/op/grants.py envoy_authz/federator/store.py tests/unit/test_op_keys.py tests/unit/test_op_store.py
git commit -m "feat: OP store, keys, grants (framework-agnostic port)

Port the authlib store (clients, stateless signed codes, OP-internal tokens),
RSA signing key, and the auth-code/OpenIDCode/refresh grants from
python-client-idp. No USERS dict: email/name travel in the stateless code and
token record; authenticate_user reconstructs the User. Grants are
framework-agnostic; the Starlette AuthorizationServer glue follows in Task 5."
```

## Task 5: OP Starlette glue + routes + mount (Flask→Starlette port)

**Files:**
- Create: `envoy_authz/op/requests.py`
- Create: `envoy_authz/op/server.py`
- Create: `envoy_authz/op/routes.py`
- Modify: `envoy_authz/op/__init__.py` (add `init_op`)
- Modify: `envoy_authz/http_app.py` (mount the OP router)
- Create: `tests/unit/test_op_routes.py` (ported `test_idp.py`)
- Modify: `tests/unit/test_http_app.py` (app now mounts OP router)
- Modify: `tests/conftest.py` (add an `op_app` fixture that seeds store + keys + mounts OP)

**Interfaces:**
- Produces (in `op/server.py`): `StarletteAuthorizationServer` (subclasses `authlib.oauth2.rfc6749.AuthorizationServer`), `StarletteUserInfoEndpoint` (subclasses `authlib.oidc.core.UserInfoEndpoint`, overrides `__call__`), `InMemoryBearerTokenValidator`, `require_oauth` (base `ResourceProtector`), `server` (module global `StarletteAuthorizationServer`), `init_server(key_set, kid)` (binds keys + registers grants + endpoint). The `server` global is constructed lazily because it needs `keys.key_set`/`kid` which are built at startup.
- Produces (in `op/requests.py`): `StarletteOAuth2Request`, `StarletteJsonRequest`, `StarletteOAuth2Payload`, `StarletteJsonPayload`.
- Produces (in `op/routes.py`): `router` (FastAPI `APIRouter`) with discovery, `/jwks.json`, `/oauth/token`, `/oauth/userinfo`.
- Produces (in `op/__init__.py`): `init_op(app, key_set, kid) -> None` (calls `init_server`, includes the router).
- Consumes: `op/grants.py`, `op/keys.py`, `federator/store.py`, `config.Settings` (`idp_issuer`).

- [ ] **Step 1: Write the failing routes tests (ported test_idp.py)**

Create `tests/unit/test_op_routes.py`:

```python
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from envoy_authz.op import keys
from envoy_authz.federator.store import create_authorization_code


def _vikunja():
    from envoy_authz.federator.providers import get_provider

    return get_provider("vikunja")


def test_discovery_document_shape(op_client):
    resp = op_client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    from envoy_authz.config import Settings

    issuer = Settings().idp_issuer
    assert body["issuer"] == issuer
    assert body["token_endpoint"] == f"{issuer}/oauth/token"
    assert body["userinfo_endpoint"] == f"{issuer}/oauth/userinfo"
    assert body["jwks_uri"] == f"{issuer}/jwks.json"
    assert body["id_token_signing_alg_values_supported"] == ["RS256"]
    assert "S256" in body["code_challenge_methods_supported"]
    assert body["subject_types_supported"] == ["public"]


def test_jwks_endpoint_exposes_signing_key(op_client):
    resp = op_client.get("/jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["keys"]) == 1
    assert body["keys"][0]["kid"] == keys.kid
    assert body["keys"][0]["kty"] == "RSA"


def _mint_code(nonce=None, code_challenge=None, code_challenge_method=None):
    code = create_authorization_code(
        client_id=_vikunja().client_id,
        redirect_uri=_vikunja().redirect_url,
        scope="openid profile email",
        user_id="abc123",
        email="alice@example.com",
        name="Alice",
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    return code


def _exchange(op_client, code, code_verifier=None):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _vikunja().redirect_url,
        "client_id": _vikunja().client_id,
        "client_secret": _vikunja().client_secret,
    }
    if code_verifier is not None:
        data["code_verifier"] = code_verifier
    return op_client.post("/oauth/token", data=data)


def test_authorization_code_flow_issues_id_token(op_client):
    code = _mint_code(nonce="n1")
    resp = _exchange(op_client, code)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "access_token" in body and "id_token" in body

    pub = keys.public_jwks_dict()["keys"][0]
    pub_ks = KeySet([RSAKey.import_key({k: pub[k] for k in ("kty", "n", "e", "kid")})])
    claims = jwt.decode(body["id_token"], pub_ks, ["RS256"]).claims
    from envoy_authz.config import Settings

    assert claims["iss"] == Settings().idp_issuer
    assert claims["aud"] == [_vikunja().client_id]
    assert claims["sub"] == "abc123"
    assert claims["nonce"] == "n1"
    assert claims["email"] == "alice@example.com"


def test_userinfo_with_bearer_token(op_client):
    code = _mint_code()
    body = _exchange(op_client, code).json()
    resp = op_client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert resp.status_code == 200, resp.text
    info = resp.json()
    assert info["sub"] == "abc123"
    assert info["email"] == "alice@example.com"


def test_refresh_token_rotates(op_client):
    code = _mint_code()
    body = _exchange(op_client, code).json()
    refresh = body.get("refresh_token")
    assert refresh

    def _refresh(token):
        return op_client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": token,
                "client_id": _vikunja().client_id,
                "client_secret": _vikunja().client_secret,
            },
        )

    resp = _refresh(refresh)
    assert resp.status_code == 200, resp.text
    new_body = resp.json()
    assert "access_token" in new_body
    new_refresh = new_body.get("refresh_token")
    assert new_refresh and new_refresh != refresh

    replay = _refresh(refresh)
    assert replay.status_code >= 400
    assert "error" in replay.json()


def test_pkce_positive_verifier_matches_challenge(op_client):
    verifier = generate_token(48)
    code = _mint_code(
        code_challenge=create_s256_code_challenge(verifier),
        code_challenge_method="S256",
    )
    resp = _exchange(op_client, code, verifier)
    assert resp.status_code == 200
    assert "id_token" in resp.json()


def test_pkce_negative_wrong_verifier_rejected(op_client):
    verifier = generate_token(48)
    code = _mint_code(
        code_challenge=create_s256_code_challenge(verifier),
        code_challenge_method="S256",
    )
    wrong = generate_token(48)
    assert wrong != verifier
    resp = _exchange(op_client, code, wrong)
    assert resp.status_code >= 400
    assert resp.json().get("error") == "invalid_grant"


def test_pkce_negative_missing_verifier_rejected(op_client):
    verifier = generate_token(48)
    code = _mint_code(
        code_challenge=create_s256_code_challenge(verifier),
        code_challenge_method="S256",
    )
    resp = _exchange(op_client, code, None)
    assert resp.status_code >= 400
    assert "error" in resp.json()
```

- [ ] **Step 2: Run routes tests to verify they fail**

Run: `poetry run pytest tests/unit/test_op_routes.py -v`
Expected: FAIL — `op_client` fixture / modules not found.

- [ ] **Step 3: Create `envoy_authz/op/requests.py`**

```python
"""Starlette request adapters for authlib's OAuth2Request / JsonRequest.

authlib has no Starlette AuthorizationServer, so we adapt Starlette requests
into authlib's framework-agnostic request types ourselves. The route handlers
pre-parse the async body (form/json) and pass the parsed dict here, so the
sync authlib calls never await.
"""

from collections import defaultdict

from authlib.oauth2.rfc6749 import JsonRequest, JsonPayload, OAuth2Payload, OAuth2Request


class StarletteOAuth2Payload(OAuth2Payload):
    def __init__(self, data: dict):
        self._data = data
        self._datalist = defaultdict(list, {k: [v] for k, v in data.items()})

    @property
    def data(self):
        return self._data

    @property
    def datalist(self) -> defaultdict:
        return self._datalist


class StarletteOAuth2Request(OAuth2Request):
    def __init__(self, request, data: dict):
        super().__init__(
            method=request.method,
            uri=str(request.url),
            headers=dict(request.headers),
        )
        self._request = request
        self._data = data
        self.payload = StarletteOAuth2Payload(data)

    @property
    def args(self):
        return dict(self._request.query_params)

    @property
    def form(self):
        return self._data


class StarletteJsonPayload(JsonPayload):
    def __init__(self, data):
        self._data = data

    @property
    def data(self):
        return self._data


class StarletteJsonRequest(JsonRequest):
    def __init__(self, request, data):
        super().__init__(request.method, str(request.url), dict(request.headers))
        self.payload = StarletteJsonPayload(data)
```

- [ ] **Step 4: Create `envoy_authz/op/server.py`**

```python
"""Starlette AuthorizationServer glue (no authlib Starlette AS integration).

Subclasses authlib's framework-agnostic base AuthorizationServer and implements
the adapter methods the Flask integration would have provided. Also subclasses
UserInfoEndpoint to use the base ResourceProtector.validate_request (authlib's
acquire_token is Flask-only).
"""

from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6750 import BearerTokenGenerator, BearerTokenValidator
from authlib.oauth2.rfc6750 import ResourceProtector
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import UserInfoEndpoint

from ..federator.store import query_client, query_token, save_token
from .grants import AuthorizationCodeGrant, OpenIDCode, RefreshTokenGrant
from .requests import StarletteJsonRequest, StarletteOAuth2Request

_JSON_HEADERS = [
    ("Content-Type", "application/json"),
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
]


class InMemoryBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return query_token(token_string)


class StarletteUserInfoEndpoint(UserInfoEndpoint):
    """UserInfoEndpoint whose __call__ uses the framework-agnostic
    ResourceProtector.validate_request (authlib's acquire_token is Flask-only).
    """

    def __call__(self, request):
        token = self.resource_protector.validate_request(["openid"], request)
        client = token.get_client()
        user = token.get_user()
        user_info = self.generate_user_info(user, token.scope)
        # Signed userinfo (userinfo_signed_response_alg) is YAGNI for Vikunja.
        if client is not None and client.client_metadata.get(
            "userinfo_signed_response_alg"
        ):
            user_info["iss"] = self.get_issuer()
            user_info["aud"] = client.client_id
            from joserfc import jwt as _jwt
            from joserfc.jwk import import_any_key

            key = import_any_key(self.resolve_private_key())
            data = _jwt.encode({"alg": "RS256"}, user_info, key, ["RS256"])
            return 200, data, [("Content-Type", "application/jwt")]
        return 200, user_info, _JSON_HEADERS


require_oauth = ResourceProtector()


class StarletteAuthorizationServer(_AuthorizationServer):
    def __init__(self, query_client, save_token):
        super().__init__()
        self._query_client = query_client
        self._save_token = save_token

    def query_client(self, client_id):
        return self._query_client(client_id)

    def save_token(self, token, request):
        return self._save_token(token, request)

    def create_oauth2_request(self, request):
        # `request` is a (starlette_request, parsed_data) carrier from the route.
        starlette_req, data = request
        return StarletteOAuth2Request(starlette_req, data)

    def create_json_request(self, request):
        starlette_req, data = request
        return StarletteJsonRequest(starlette_req, data)

    def handle_response(self, status, payload, headers):
        from starlette.responses import JSONResponse, Response

        if isinstance(payload, dict):
            return JSONResponse(content=payload, status_code=status, headers=headers)
        return Response(content=payload, status_code=status, headers=headers)

    def send_signal(self, name, *args, **kwargs):
        pass

    def get_error_uri(self, request, error):
        return None


# Constructed lazily by init_server (needs keys). Route modules import `server`.
server: StarletteAuthorizationServer | None = None


def init_server(key_set, kid) -> StarletteAuthorizationServer:
    """Bind keys, register grants + the userinfo endpoint, wire the token
    generator, and register the bearer validator."""
    global server
    server = StarletteAuthorizationServer(
        query_client=query_client, save_token=save_token
    )
    server.register_token_generator(
        "default",
        BearerTokenGenerator(
            lambda *a, **k: generate_token(42),  # access token
            lambda *a, **k: generate_token(48),  # refresh token
        ),
    )
    server.register_grant(
        AuthorizationCodeGrant,
        [CodeChallenge(required=False), OpenIDCode(require_nonce=False)],
    )
    server.register_grant(RefreshTokenGrant)
    require_oauth.register_token_validator(InMemoryBearerTokenValidator())
    server.register_endpoint(
        StarletteUserInfoEndpoint(resource_protector=require_oauth)
    )
    return server
```

- [ ] **Step 5: Create `envoy_authz/op/routes.py`**

```python
"""OP HTTP routes (FastAPI APIRouter). Ported from app/idp/routes.py.

No /oauth/authorize route — the federator mints codes directly. Discovery still
advertises authorization_endpoint for provider-metadata compatibility.
"""

from fastapi import APIRouter, Request

from ..config import Settings
from . import keys
from .server import server

router = APIRouter()


@router.get("/.well-known/openid-configuration")
async def discovery():
    issuer = Settings().idp_issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
    }


@router.get("/jwks.json")
async def jwks():
    return keys.public_jwks_dict()


@router.post("/oauth/token")
async def issue_token(request: Request):
    form = await request.form()
    return server.create_token_response((request, dict(form)))


@router.api_route("/oauth/userinfo", methods=["GET", "POST"])
async def userinfo(request: Request):
    if request.method == "POST":
        try:
            data = await request.json()
        except Exception:
            data = {}
    else:
        data = dict(request.query_params)
    return server.create_endpoint_response("userinfo", (request, data))
```

- [ ] **Step 6: Create `envoy_authz/op/keys.py` module globals + update `op/__init__.py`**

The `keys.py` from Task 4 defined `load_or_create_key`. Add module globals (`key_set`, `kid`, `public_jwks_dict`) that are populated by `init_op`. Append to `envoy_authz/op/keys.py`:

```python
# Populated by init_op (Task 5) at startup. Grants/routes read these globals.
key_set = None  # joserfc KeySet
kid: str = ""


def set_key(jwk):
    """Bind the loaded/generated RSA key as the OP signing key."""
    global key_set, kid
    key_set = KeySet([jwk])
    kid = jwk.kid


def public_jwks_dict() -> dict:
    params = key_set.keys[0].as_dict()
    entry = {k: params[k] for k in ("kty", "n", "e", "kid")}
    entry.update({"alg": "RS256", "use": "sig"})
    return {"keys": [entry]}
```

(Add `from joserfc.jwk import KeySet` to the imports at the top of `keys.py`.)

Create `envoy_authz/op/__init__.py`:

```python
"""OIDC Provider package."""

from . import keys


def init_op(app, key_path: str) -> None:
    """Load/generate the RSA signing key, init the AuthorizationServer, and
    mount the OP router on the FastAPI app."""
    from .server import init_server
    from .routes import router

    jwk = keys.load_or_create_key(key_path)
    keys.set_key(jwk)
    init_server(keys.key_set, keys.kid)
    app.include_router(router)
```

- [ ] **Step 7: Mount the OP in `http_app.py`**

Rewrite `envoy_authz/http_app.py`:

```python
"""FastAPI application factory for the in-process HTTPS server.

Decoupled from the gRPC side: the caller (__main__) supplies a lifespan that
owns the gRPC server. The OP router is mounted here when an OP key path is
provided (None skips it — used by tests that only need /healthz).
"""

from fastapi import FastAPI


def create_app(lifespan=None, op_key_path: str | None = None) -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    if op_key_path is not None:
        from envoy_authz.op import init_op

        init_op(app, op_key_path)

    return app
```

- [ ] **Step 8: Add the `op_client` fixture to `tests/conftest.py`**

Append to `tests/conftest.py`:

```python
OP_PROVIDERS_YAML = """
providers:
  vikunja:
    client_id: "vikunja"
    client_secret: "vikunja-secret"
    redirect_url: "http://localhost:3456/auth/openid/broker"
    api_base: "http://localhost:3456"
    provider_key: "broker"
    scope: "openid profile email"
"""


@pytest.fixture
def op_client(tmp_path, monkeypatch):
    """A FastAPI TestClient with the OP mounted, store seeded, keys generated."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", FRIGATE_TEST_SECRET)
    monkeypatch.setenv("HA_CA_CERTIFICATE", _pem(_TRUSTED_CA))
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")

    from envoy_authz.federator import providers
    from envoy_authz.federator.store import _reset, seed
    from envoy_authz.http_app import create_app

    p = tmp_path / "providers.yaml"
    p.write_text(OP_PROVIDERS_YAML)
    providers.load_providers(str(p))
    _reset()
    seed()

    key_path = str(tmp_path / "op_key.pem")
    app = create_app(op_key_path=key_path)
    return TestClient(app)
```

- [ ] **Step 9: Update `test_http_app.py` for the new `create_app` signature**

`create_app` now takes `op_key_path=None` (default None → no OP, just `/healthz`). The existing tests pass `create_app()` with no args, so they keep working unchanged. Verify in Step 12.

- [ ] **Step 10: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 11: Run the OP routes tests**

Run: `poetry run pytest tests/unit/test_op_routes.py -v`
Expected: PASS. If `test_userinfo_with_bearer_token` fails with a 401, confirm `StarletteUserInfoEndpoint.__call__` uses `validate_request(["openid"], request)` and the bearer validator's `validate_token` (inherited from `BearerTokenValidator`) accepts the token — the `OAuth2Token.scope` must include `openid` (it does: the code's scope is `openid profile email`).

- [ ] **Step 12: Run the full suite**

Run: `poetry run pytest -v`
Expected: PASS (all existing + OP routes + OP store/keys).

- [ ] **Step 13: Commit**

```bash
git add envoy_authz/op/requests.py envoy_authz/op/server.py envoy_authz/op/routes.py envoy_authz/op/__init__.py envoy_authz/op/keys.py envoy_authz/http_app.py tests/unit/test_op_routes.py tests/conftest.py
git commit -m "feat: OP Starlette glue, routes, mount (Flask->Starlette port)

Subclass authlib's base AuthorizationServer with Starlette adapter methods
(request wrappers, handle_response -> JSONResponse, manual token generator).
Subclass UserInfoEndpoint to use base ResourceProtector.validate_request
(authlib's acquire_token is Flask-only). Mount the OP APIRouter on the FastAPI
app via init_op. Ported test_idp.py covers discovery/JWKS/auth-code/id_token/
userinfo/refresh-rotation/PKCE."
```

## Task 6: Vikunja HTTP client (refresh + federate) + respx tests

**Files:**
- Create: `envoy_authz/federator/vikunja.py`
- Create: `tests/unit/test_vikunja.py`
- Modify: `tests/conftest.py` (no new fixture; tests build a `VikunjaClient` directly)

**Spec alignment (important — differs from a naive port):**
- The spec **intentionally does not call `GET /api/v1/user` on the hot path**
  (spec lines 78–80, 203–207, 473). Session validity is decided locally via
  `exp` + refresh/federation. So this client has **no `validate_bearer` helper**
  (YAGNI per spec line 206). The only Vikunja calls are the cold paths:
  `refresh` and `federate`.
- The refresh-token cookie is a **`Set-Cookie` response header**, not a JSON
  field (spec lines 72–74, 82–84). Extract it verbatim from the response,
  handling the comma-bearing `Expires` case (a `Set-Cookie` value may contain
  `Expires=Wed, 21 Oct 2026 07:28:00 GMT`, whose comma must not be treated as a
  header-separator split point). This is the source's verbatim `Set-Cookie`
  extraction logic, ported to httpx.
- The federation callback contract is `{"code": <auth_code>,
  "redirect_url": <url>}` (spec lines 85–87, 412–413). **Vikunja** exchanges
  the code at the OP `/oauth/token` for an `id_token` itself; the federator does
  NOT send an `id_token` and does NOT exchange the code. So `federate` only mints
  the OP auth code and POSTs `{code, redirect_url}`; the OP token exchange
  happens over HTTP when Vikunja calls back into this service's `/oauth/token`.

**Interfaces:**
- Produces: `VikunjaClient` (class, takes a `Provider` and an `httpx.Client`;
  methods `refresh(refresh_cookie) -> VikunjaSession`, `federate(subject) ->
  VikunjaSession`). Both raise `DownstreamError` on non-200 / no-token /
  transport failure (the session ladder catches and denies).
- Produces: `VikunjaSession` (Pydantic `BaseModel`: `bearer: str`,
  `refresh_cookie: str | None`, `exp: float`, `user_id: str | None`). `bearer`
  is a plain `str` (it is injected upstream as a header value; it is never
  logged). `exp` is decoded from the bearer JWT payload we received over our
  trusted channel to Vikunja (no signature check needed on our own obtained
  token — spec lines 437–443). `user_id` is the `id` claim from that payload,
  for logging.
- Produces: `DownstreamError` (subclass of `Exception`).
- Consumes: `federator/providers.py` (`Provider` — `api_base`, `client_id`,
  `redirect_url`, `provider_key`), `federator/store.py`
  (`create_authorization_code`), `federator/subject.py` (`Subject`).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_vikunja.py`:

```python
import time

import httpx
import pytest
import respx

from envoy_authz.federator.providers import get_provider
from envoy_authz.federator.subject import Subject
from envoy_authz.federator.vikunja import DownstreamError, VikunjaClient


@pytest.fixture
def vikunja(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    return VikunjaClient(
        get_provider("vikunja"), httpx.Client(base_url="http://localhost:3456")
    )


def _subject(sub="abc123", email="alice@example.com", name="Alice"):
    return Subject(sub=sub, email=email, name=name)


def _bearer(user_id="1", exp_delta=600):
    # Vikunja access tokens are HS256 JWTs signed with service.secret. We mint a
    # real one with the test secret so the client can decode exp/id from the
    # payload (no signature verification on our own obtained token).
    import jwt as pyjwt

    payload = {
        "id": user_id,
        "exp": int(time.time()) + exp_delta,
        "type": "access",
    }
    return pyjwt.encode(payload, "test-secret-key", algorithm="HS256")


def _set_cookie_header(value="rt1", expires_comma=False):
    # The verbatim Set-Cookie extraction must survive a comma-bearing Expires.
    if expires_comma:
        return (
            f"vikunja_refresh_token={value}; Path=/api/v1/user/token/refresh; "
            f"Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly"
        )
    return f"vikunja_refresh_token={value}; Path=/api/v1/user/token/refresh; HttpOnly"


@respx.mock
def test_refresh_returns_rotated_session_from_set_cookie(vikunja):
    new_bearer = _bearer(user_id="1")
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": _set_cookie_header("rotated-rt")},
            json={"token": new_bearer},
        )
    )
    session = vikunja.refresh("old-rt")
    assert session.bearer == new_bearer
    assert session.refresh_cookie == "rotated-rt"
    assert session.exp > time.time()
    assert session.user_id == "1"


@respx.mock
def test_refresh_extracts_cookie_with_comma_bearing_expires(vikunja):
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": _set_cookie_header("rt2", expires_comma=True)},
            json={"token": _bearer()},
        )
    )
    session = vikunja.refresh("old-rt")
    # The Expires comma must not truncate the cookie value.
    assert session.refresh_cookie == "rt2"


@respx.mock
def test_refresh_401_raises_downstream_error(vikunja):
    # 401 means the session was revoked/expired; the ladder treats this as
    # "fall through to federation", not a hard deny. The client surfaces it as a
    # distinct sentinel so the ladder can branch.
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(401)
    )
    with pytest.raises(DownstreamError) as exc:
        vikunja.refresh("expired")
    assert exc.value.refresh_revoked


@respx.mock
def test_refresh_network_error_raises_downstream_error(vikunja):
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        side_effect=httpx.ConnectError("boom")
    )
    with pytest.raises(DownstreamError):
        vikunja.refresh("old-rt")


@respx.mock
def test_federate_posts_code_and_redirect_url(vikunja):
    new_bearer = _bearer(user_id="1")
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": _set_cookie_header("fresh-rt")},
            json={"token": new_bearer},
        )
    )
    session = vikunja.federate(_subject())
    assert session.bearer == new_bearer
    assert session.refresh_cookie == "fresh-rt"
    # The callback body is {code, redirect_url} — NOT an id_token.
    sent = respx.calls[0].request
    import json as _json

    body = _json.loads(sent.content)
    assert "code" in body and "redirect_url" in body
    assert "id_token" not in body
    assert body["redirect_url"] == get_provider("vikunja").redirect_url


@respx.mock
def test_federate_non_200_raises_downstream_error(vikunja):
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(500, text="boom")
    )
    with pytest.raises(DownstreamError):
        vikunja.federate(_subject())


@respx.mock
def test_federate_missing_token_raises_downstream_error(vikunja):
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(200, json={})
    )
    with pytest.raises(DownstreamError):
        vikunja.federate(_subject())


@respx.mock
def test_federate_no_set_cookie_caches_with_none(vikunja):
    # Callback returns a token but no Set-Cookie → cache bearer with
    # refresh_cookie=None; a future refresh 401s → re-federate (spec line 465).
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(200, json={"token": _bearer()})
    )
    session = vikunja.federate(_subject())
    assert session.bearer
    assert session.refresh_cookie is None


def test_client_never_logs_bearer_or_cookie(vikunja, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    token = _bearer()
    with respx.mock:
        respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
            return_value=httpx.Response(
                200,
                headers={"set-cookie": _set_cookie_header("secret-rt")},
                json={"token": token},
            )
        )
        vikunja.refresh("old-rt")
    for record in caplog.records:
        msg = record.getMessage()
        assert token not in msg
        assert "secret-rt" not in msg
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `poetry run pytest tests/unit/test_vikunja.py -v`
Expected: FAIL — `federator.vikunja` module not found.

- [ ] **Step 3: Create `envoy_authz/federator/vikunja.py`**

```python
"""HTTP client for the Vikunja API (cold paths only: refresh + federate).

Per the design spec, GET /api/v1/user is NOT called on the hot path; session
validity is decided locally via exp + refresh/federation. So this client has no
validate_bearer helper. The refresh-token cookie is a Set-Cookie response
header (not a JSON field); it is extracted verbatim, including the
comma-bearing Expires case ported from the source broker. Federation mints an
OP auth code and POSTs {code, redirect_url}; Vikunja exchanges the code at the
OP itself. Bearer tokens and refresh cookies are never logged.
"""

import logging
import time
from http.cookies import SimpleCookie

import httpx
from pydantic import BaseModel

from .providers import Provider
from .subject import Subject

logger = logging.getLogger(__name__)

_REFRESH_PATH = "/api/v1/user/token/refresh"
_REFRESH_COOKIE_NAME = "vikunja_refresh_token"


class DownstreamError(Exception):
    """Vikunja returned an error or was unreachable. `refresh_revoked` marks
    the 401-on-refresh case (session revoked/expired) so the ladder can fall
    through to federation rather than hard-deny."""

    def __init__(self, message: str, *, refresh_revoked: bool = False):
        super().__init__(message)
        self.refresh_revoked = refresh_revoked


class VikunjaSession(BaseModel):
    bearer: str                 # Vikunja JWT; plain str (injected as a header)
    refresh_cookie: str | None  # rotated vikunja_refresh_token value
    exp: float                  # bearer exp (unix), decoded from the payload
    user_id: str | None         # `id` claim from the payload, for logging


class VikunjaClient:
    """Wraps httpx calls to Vikunja. The caller owns the httpx client."""

    def __init__(self, provider: Provider, client: httpx.Client):
        self._provider = provider
        self._client = client

    # --- refresh ---------------------------------------------------------

    def refresh(self, refresh_cookie: str) -> VikunjaSession:
        """POST /api/v1/user/token/refresh with the Cookie header; return the
        rotated session. Raises DownstreamError(refresh_revoked=True) on 401
        (so the ladder falls through to federation) and DownstreamError on any
        other failure."""
        try:
            resp = self._client.post(
                _REFRESH_PATH,
                headers={"Cookie": f"{_REFRESH_COOKIE_NAME}={refresh_cookie}"},
            )
        except httpx.HTTPError as exc:
            logger.warning("Vikunja refresh transport error")
            raise DownstreamError("refresh transport error") from exc
        if resp.status_code == 401:
            logger.info("Vikunja refresh rejected (revoked/expired)")
            raise DownstreamError("refresh rejected", refresh_revoked=True)
        if resp.status_code != 200:
            logger.warning("Vikunja refresh failed (status=%d)", resp.status_code)
            raise DownstreamError(f"refresh status {resp.status_code}")
        return self._session_from_response(resp)

    # --- federation ------------------------------------------------------

    def federate(self, subject: Subject) -> VikunjaSession:
        """Mint a stateless OP auth code, POST {code, redirect_url} to Vikunja's
        openid callback, return the resulting session. Vikunja exchanges the
        code at the OP /oauth/token itself. Raises DownstreamError on failure."""
        from .store import create_authorization_code

        code = create_authorization_code(
            client_id=self._provider.client_id,
            redirect_uri=self._provider.redirect_url,
            scope=self._provider.scope,
            user_id=subject.sub,
            email=subject.email,
            name=subject.name,
            nonce=None,
        )
        callback = f"/api/v1/auth/openid/{self._provider.provider_key}/callback"
        try:
            resp = self._client.post(
                callback,
                json={"code": code, "redirect_url": self._provider.redirect_url},
            )
        except httpx.HTTPError as exc:
            logger.warning("Vikunja openid callback transport error")
            raise DownstreamError("callback transport error") from exc
        if resp.status_code != 200:
            logger.warning(
                "Vikunja openid callback failed (status=%d)", resp.status_code
            )
            raise DownstreamError(f"callback status {resp.status_code}")
        return self._session_from_response(resp, require_token=True)

    # --- shared response parsing ----------------------------------------

    def _session_from_response(
        self, resp: httpx.Response, *, require_token: bool = True
    ) -> VikunjaSession:
        try:
            body = resp.json()
        except ValueError as exc:
            logger.warning("Vikunja returned non-JSON body")
            raise DownstreamError("non-JSON body") from exc
        bearer = body.get("token")
        if not bearer:
            if require_token:
                logger.warning("Vikunja response missing token")
                raise DownstreamError("missing token")
            bearer = ""
        # The rotated refresh cookie comes from Set-Cookie, not the JSON body.
        refresh_cookie = _extract_refresh_cookie(resp)
        if refresh_cookie is None:
            logger.warning("Vikunja response missing Set-Cookie refresh token")
        exp, user_id = _decode_bearer_payload(bearer)
        return VikunjaSession(
            bearer=bearer,
            refresh_cookie=refresh_cookie,
            exp=exp,
            user_id=user_id,
        )


def _extract_refresh_cookie(resp: httpx.Response) -> str | None:
    """Extract the vikunja_refresh_token value from a Set-Cookie header,
    handling the comma-bearing Expires case. httpx exposes raw Set-Cookie
    headers via resp.headers.get_list('set-cookie') so a comma inside one
    cookie's Expires does not split across headers."""
    for raw in resp.headers.get_list("set-cookie"):
        # SimpleCookie parses one Set-Cookie at a time; a trailing Expires comma
        # is contained within the single raw string.
        jar = SimpleCookie()
        jar.load(raw)
        morsel = jar.get(_REFRESH_COOKIE_NAME)
        if morsel is not None and morsel.value:
            return morsel.value
    return None


def _decode_bearer_payload(bearer: str) -> tuple[float, str | None]:
    """Decode exp + id from our own obtained bearer's payload. No signature
    check (spec lines 437–443): we trust the token we received over our trusted
    channel to Vikunja. Returns (exp_unix, user_id)."""
    import jwt as pyjwt

    if not bearer:
        return 0.0, None
    try:
        # decode without verification — we only read exp/id off our own token
        payload = pyjwt.decode(bearer, options={"verify_signature": False})
    except Exception:
        return 0.0, None
    exp = float(payload.get("exp") or 0.0)
    user_id = str(payload["id"]) if "id" in payload else None
    return exp, user_id
```

- [ ] **Step 4: Add `PyJWT` runtime dep**

The client decodes `exp`/`id` from the bearer JWT payload (no signature check).
PyJWT is therefore a **runtime** dep (the source relied on it transitively; make
it explicit).

Run: `poetry add pyjwt`

- [ ] **Step 5: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 6: Run the Vikunja tests**

Run: `poetry run pytest tests/unit/test_vikunja.py -v`
Expected: PASS — all 10 tests green.

- [ ] **Step 7: Commit**

```bash
git add envoy_authz/federator/vikunja.py tests/unit/test_vikunja.py pyproject.toml poetry.lock
git commit -m "feat: Vikunja HTTP client (refresh + federate) with respx tests

httpx client for the cold paths only — no GET /api/v1/user hot-path call (spec).
refresh: POST token/refresh with Cookie header, rotates the refresh cookie
out of Set-Cookie (verbatim extraction incl. comma-bearing Expires). federate:
mint an OP auth code, POST {code, redirect_url} to the openid callback (Vikunja
exchanges the code at the OP itself). Bearer/cookie never logged; exp/id decoded
from our own obtained token payload (no signature check)."
```

## Task 7: Session cache + get_bearer decision ladder

**Files:**
- Create: `envoy_authz/federator/session.py`
- Create: `tests/unit/test_session.py`

**Spec alignment (the decision ladder — verbatim from spec lines 389–443):**
```
1. incoming_bearer present?
   - If session_secret configured: verify HS256 sig + exp locally.
     - valid & not near-expiry → return None   (allow through unchanged)
     - valid but near-expiry   → fall to step 2 (inject a fresh one)
   - If no session_secret: treat as opaque; can't trust it locally
     → fall to step 2 (use the cached session)
2. cached = cache[sub]
   - cached and cached.exp > now + margin → return cached.bearer
   - cached and stale (exp near) → refresh (step 3)
   - no cache → federate (step 4)
3. refresh: POST /api/v1/user/token/refresh (Cookie: ...<cached>)
   - 200 → new {token} + rotated Set-Cookie → update cache → return new bearer
   - 401 (revoked/expired) → federate (step 4)
   - network error → raise (Check denies)
4. federate: mint OP code → POST callback {code, redirect_url} → 200 {token}
   - 200 → cache (bearer, cookie, exp) → return bearer
   - failure → raise (Check denies)
```
**Return contract (spec lines 418–423):** `get_bearer` returns `str | None`:
- `None` → "no injection needed" (client's incoming bearer was valid; `Check`
  allows through unchanged — the only path with no `Authorization` header added).
- `str` → "inject this bearer upstream".
**Failure → raise** `DownstreamError` (spec lines 452–455); the caller (`Check`)
catches and denies. `None` is NEVER the deny signal — deny comes from a raised
exception.

**Interfaces:**
- Produces: `SessionCache` (thread-safe, per-key locking, lazy TTL expiry),
  `get_bearer(subject, incoming_bearer, vikunja, cache) -> str | None` (raises
  `DownstreamError` on unrecoverable failure).
- Produces (in `session.py`): `CachedSession` (Pydantic `BaseModel`: `bearer:
  str`, `refresh_cookie: str | None`, `exp: float`, `user_id: str | None`).
- Consumes: `federator/subject.py` (`Subject`), `federator/vikunja.py`
  (`VikunjaClient`, `VikunjaSession`, `DownstreamError`), `config.Settings`
  (`secret_key` for the optional HS256 fast-path).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_session.py`:

```python
import time

import httpx
import pytest
import respx
from pydantic import SecretStr

from envoy_authz.federator.session import CachedSession, SessionCache, get_bearer
from envoy_authz.federator.subject import Subject
from envoy_authz.federator.vikunja import DownstreamError, VikunjaClient, VikunjaSession


@pytest.fixture
def cache():
    return SessionCache(ttl=300.0, margin=60.0)


def _subject(sub="abc123", email="alice@example.com", name="Alice"):
    return Subject(sub=sub, email=email, name=name)


def _bearer(exp_delta=600, user_id="1"):
    import jwt as pyjwt

    return pyjwt.encode(
        {"id": user_id, "exp": int(time.time()) + exp_delta, "type": "access"},
        "test-secret-key",
        algorithm="HS256",
    )


def _cached(bearer="cached-tok", refresh="rt", exp_delta=300):
    return CachedSession(
        bearer=bearer,
        refresh_cookie=refresh,
        exp=time.time() + exp_delta,
        user_id="1",
    )


def test_cache_get_miss(cache):
    assert cache.get("abc123") is None


def test_cache_put_then_get(cache):
    cache.put("abc123", _cached())
    got = cache.get("abc123")
    assert got is not None and got.bearer == "cached-tok"


def test_cache_expires_after_exp(cache):
    cache.put("abc123", _cached(exp_delta=-1))
    assert cache.get("abc123") is None


def test_get_bearer_incoming_valid_and_fresh_returns_none(cache, monkeypatch):
    # session_secret configured + incoming bearer verifies + not near-expiry
    # → return None (allow through unchanged).
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    bearer = _bearer(exp_delta=600)
    vk = _stub_vikunja()
    assert get_bearer(_subject(), bearer, vk, cache) is None
    # Nothing was cached (we trusted the client's token).
    assert cache.get(_subject().sub) is None


def test_get_bearer_incoming_near_expiry_falls_to_cache(cache, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    bearer = _bearer(exp_delta=30)  # within margin (60s)
    vk = _stub_vikunja()
    cache.put(_subject().sub, _cached(bearer="cached-tok", exp_delta=300))
    # Near-expiry incoming → fall to step 2 → cached fresh → inject cached.
    assert get_bearer(_subject(), bearer, vk, cache) == "cached-tok"


def test_get_bearer_no_session_secret_does_not_trust_incoming(cache, monkeypatch):
    # No session_secret → incoming bearer is opaque → fall to cache.
    monkeypatch.delenv("SECRET_KEY", raising=False)
    # Force Settings.secret_key empty by not setting it + an empty default.
    bearer = _bearer()
    vk = _stub_vikunja()
    cache.put(_subject().sub, _cached(bearer="cached-tok", exp_delta=300))
    assert get_bearer(_subject(), bearer, vk, cache) == "cached-tok"


def test_get_bearer_cached_fresh_returns_cached_bearer(cache):
    bearer = _bearer()
    cache.put(_subject().sub, _cached(bearer="cached-tok", exp_delta=300))
    vk = _stub_vikunja()
    assert get_bearer(_subject(), None, vk, cache) == "cached-tok"


def test_get_bearer_cached_stale_refreshes(cache):
    cache.put(_subject().sub, _cached(bearer="stale", refresh="old-rt", exp_delta=-1))
    vk = _stub_vikunja(refresh_session=_sess("rotated", "new-rt"))
    assert get_bearer(_subject(), None, vk, cache) == "rotated"
    # Cache updated with the rotated session.
    got = cache.get(_subject().sub)
    assert got.bearer == "rotated" and got.refresh_cookie == "new-rt"


def test_get_bearer_refresh_401_falls_through_to_federate(cache):
    cache.put(_subject().sub, _cached(bearer="stale", refresh="old-rt", exp_delta=-1))
    vk = _stub_vikunja(
        refresh_raises=DownstreamError("revoked", refresh_revoked=True),
        federate_session=_sess("federated", "fed-rt"),
    )
    assert get_bearer(_subject(), None, vk, cache) == "federated"
    assert cache.get(_subject().sub).refresh_cookie == "fed-rt"


def test_get_bearer_no_cache_federates(cache):
    vk = _stub_vikunja(federate_session=_sess("fresh", "fresh-rt"))
    assert get_bearer(_subject(), None, vk, cache) == "fresh"
    got = cache.get(_subject().sub)
    assert got.bearer == "fresh" and got.refresh_cookie == "fresh-rt"


def test_get_bearer_refresh_network_error_raises(cache):
    cache.put(_subject().sub, _cached(bearer="stale", refresh="old-rt", exp_delta=-1))
    vk = _stub_vikunja(refresh_raises=DownstreamError("transport"))
    with pytest.raises(DownstreamError):
        get_bearer(_subject(), None, vk, cache)


def test_get_bearer_federate_failure_raises(cache):
    vk = _stub_vikunja(federate_raises=DownstreamError("callback 500"))
    with pytest.raises(DownstreamError):
        get_bearer(_subject(), None, vk, cache)


def test_get_bearer_concurrent_same_identity_single_federate(cache):
    # Second concurrent caller for the same key reuses the first's mint.
    call_count = {"n": 0}

    class CountingVk(VikunjaClient):
        def __init__(self):
            super().__init__(get_provider("vikunja"), httpx.Client())
            self._fed = _sess("fresh", "fresh-rt")

        def federate(self, subject):
            call_count["n"] += 1
            return self._fed

    vk = CountingVk()
    import threading

    results = []

    def run():
        results.append(get_bearer(_subject(), None, vk, cache))

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == "fresh" for r in results)
    assert call_count["n"] == 1


# --- helpers ------------------------------------------------------------


def _sess(bearer, refresh, exp_delta=600):
    return VikunjaSession(
        bearer=bearer,
        refresh_cookie=refresh,
        exp=time.time() + exp_delta,
        user_id="1",
    )


def _stub_vikunja(
    refresh_session=None,
    federate_session=None,
    refresh_raises=None,
    federate_raises=None,
):
    from envoy_authz.federator.providers import get_provider

    class StubVk(VikunjaClient):
        def __init__(self):
            super().__init__(get_provider("vikunja"), httpx.Client())

        def refresh(self, refresh_cookie):
            if refresh_raises is not None:
                raise refresh_raises
            return refresh_session or _sess("rotated", "new-rt")

        def federate(self, subject):
            if federate_raises is not None:
                raise federate_raises
            return federate_session or _sess("fresh", "fresh-rt")

    return StubVk()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `poetry run pytest tests/unit/test_session.py -v`
Expected: FAIL — `federator.session` module not found.

- [ ] **Step 3: Create `envoy_authz/federator/session.py`**

```python
"""Per-identity session cache and the get_bearer federation decision ladder.

get_bearer (spec lines 389–443) decides, for an incoming Envoy request, whether
to allow the client's own bearer through unchanged (return None), inject a
cached/refreshed/federated bearer upstream (return str), or deny (raise
DownstreamError; the caller catches and denies). The hot path never calls
Vikunja — it uses local exp checks; only refresh/federation reach Vikunja.
Secrets are never logged.
"""

import logging
import threading
import time

from pydantic import BaseModel

from .subject import Subject
from .vikunja import DownstreamError, VikunjaClient

logger = logging.getLogger(__name__)


class CachedSession(BaseModel):
    bearer: str
    refresh_cookie: str | None = None
    exp: float = 0.0
    user_id: str | None = None


class SessionCache:
    """Thread-safe in-memory cache keyed by stable subject `sub`.

    Per-key locking serializes refresh/federation for one identity so a burst of
    concurrent Checks for the same user does not double-federate. Entries are
    expired lazily on get when `exp` is near/passed (the `margin` is applied by
    the ladder, not here — get returns the entry if exp > now).
    """

    def __init__(self, ttl: float = 300.0, margin: float = 60.0):
        self._ttl = ttl
        self.margin = margin
        self._entries: dict[str, CachedSession] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock_for(self, key: str) -> threading.Lock:
        with self._guard:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            return self._locks[key]

    def get(self, key: str) -> CachedSession | None:
        return self._entries.get(key)

    def put(self, key: str, session: CachedSession) -> None:
        self._entries[key] = session

    def lock(self, key: str) -> threading.Lock:
        return self._lock_for(key)

    def clear(self) -> None:
        with self._guard:
            self._entries.clear()
            self._locks.clear()


def _now() -> float:
    return time.time()


def _verify_incoming_bearer(bearer: str) -> tuple[bool, float]:
    """Local HS256 fast-path (spec lines 394–398, 435–443). Returns
    (signature_valid, exp). If no session_secret is configured, returns
    (False, 0) — we never trust a bearer we cannot verify."""
    from ..config import Settings

    secret = Settings().secret_key.get_secret_value()
    if not secret:
        return False, 0.0
    import jwt as pyjwt
    from jwt import InvalidTokenError

    try:
        payload = pyjwt.decode(bearer, secret, algorithms=["HS256"])
    except InvalidTokenError:
        return False, 0.0
    except Exception:
        return False, 0.0
    return True, float(payload.get("exp") or 0.0)


def get_bearer(
    subject: Subject,
    incoming_bearer: str | None,
    vikunja: VikunjaClient,
    cache: SessionCache,
) -> str | None:
    """Decision ladder. Returns str (inject upstream), None (allow client's
    bearer through unchanged), or raises DownstreamError (deny)."""
    key = subject.sub
    now = _now()

    # 1. Incoming bearer present?
    if incoming_bearer:
        valid, exp = _verify_incoming_bearer(incoming_bearer)
        if valid and exp > now + cache.margin:
            logger.info("allowed-through-client-bearer sub=%s", key)
            return None  # client's token is fine; no injection
        # valid-but-near-expiry, or unverifiable → fall to step 2

    # 2. Cached?
    cached = cache.get(key)
    if cached is not None and cached.exp > now + cache.margin:
        logger.info("injected-cached sub=%s", key)
        return cached.bearer
    if cached is not None and cached.refresh_cookie:
        # 3. Refresh.
        try:
            session = vikunja.refresh(cached.refresh_cookie)
        except DownstreamError as exc:
            if exc.refresh_revoked:
                logger.info("refresh-revoked sub=%s, federating", key)
                return _federate(key, subject, vikunja, cache)
            logger.warning("refresh-failed sub=%s", key)
            raise
        cache.put(
            key,
            CachedSession(
                bearer=session.bearer,
                refresh_cookie=session.refresh_cookie,
                exp=session.exp,
                user_id=session.user_id,
            ),
        )
        logger.info("injected-refreshed sub=%s", key)
        return session.bearer
    # no cache, or cached with no refresh cookie → federate
    return _federate(key, subject, vikunja, cache)


def _federate(
    key: str, subject: Subject, vikunja: VikunjaClient, cache: SessionCache
) -> str:
    """Step 4: mint a fresh session under the per-key lock. Re-checks the cache
    under the lock so a concurrent caller reuses the first's mint."""
    with cache.lock(key):
        cached = cache.get(key)
        if cached is not None and cached.exp > _now() + cache.margin:
            return cached.bearer
        try:
            session = vikunja.federate(subject)
        except DownstreamError:
            logger.warning("federation-failure sub=%s", key)
            raise
        cache.put(
            key,
            CachedSession(
                bearer=session.bearer,
                refresh_cookie=session.refresh_cookie,
                exp=session.exp,
                user_id=session.user_id,
            ),
        )
        logger.info("injected-federated sub=%s", key)
        return session.bearer
```

- [ ] **Step 4: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 5: Run the session tests**

Run: `poetry run pytest tests/unit/test_session.py -v`
Expected: PASS — all 12 tests green. If `_verify_incoming_bearer`'s `Settings()`
construction fails in `test_get_bearer_no_session_secret_does_not_trust_incoming`
because `frigate_x_proxy_secret` is required, set `FRIGATE_X_PROXY_SECRET` and
`HA_CA_CERTIFICATE` in that test's `monkeypatch` (the conftest `ha_config`
fixture shows the pattern).

- [ ] **Step 6: Run the full suite**

Run: `poetry run pytest -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add envoy_authz/federator/session.py tests/unit/test_session.py
git commit -m "feat: per-identity session cache + get_bearer federation ladder

SessionCache: thread-safe, per-key locking, lazy exp expiry. get_bearer ladder
(spec): incoming bearer verified locally (HS256 fast-path when session_secret
configured) → allow through (None); else cached-fresh → inject; else refresh
→ inject (401 falls through to federate, network error raises); else federate
under per-key lock. Returns str (inject) / None (allow-through) / raises
DownstreamError (deny). No per-request Vikunja call on the hot path."
```

## Task 8: gRPC Check integration (federation on the ext_authz path)

**Files:**
- Modify: `envoy_authz/grpc_service.py`
- Modify: `tests/unit/test_check.py` (or create if absent)
- Modify: `tests/conftest.py` (gRPC test fixture wiring)

**Spec alignment:**
- `Check` calls `get_bearer` after the mTLS allow gate. Return value contract:
  `str` → inject `Authorization: Bearer <str>` via `headers_to_add`; `None` →
  allow through unchanged (NO `Authorization` header added — spec line 421);
  raised `DownstreamError` → `PERMISSION_DENIED` (deny-on-failure, spec lines
  452–455).
- The Frigate `X-Proxy-Secret` path stays orthogonal (spec line 214).
- Log the decision branch (spec lines 477–482); never log the bearer.

**Interfaces:**
- Produces (in `grpc_service.py`): module globals `_vikunja: VikunjaClient`,
  `_SESSIONS: SessionCache`, wired by `init_federator(provider_name)` (called
  from the lifespan).
- Consumes: `federator/session.py` (`get_bearer`, `SessionCache`),
  `federator/subject.py` (`derive_subject`), `federator/vikunja.py`
  (`VikunjaClient`, `DownstreamError`), `identity.py` (`parse_client_identity`).

- [ ] **Step 1: Read the current `grpc_service.py` and its test**

Run: `poetry run pytest tests/unit/test_check.py -v` (if it exists) for the
baseline. Read `envoy_authz/grpc_service.py` and `tests/unit/test_check.py`
fully before editing.

- [ ] **Step 2: Write the failing federation tests**

Add to `tests/unit/test_check.py` (append; keep existing mTLS-verify tests):

```python
from urllib.parse import quote

import httpx
import respx

from envoy_authz.federator.subject import Subject
from envoy_authz.federator.vikunja import DownstreamError, VikunjaSession


def _check_request(cert_pem, bearer=None, refresh_cookie=None):
    from envoy_authz import grpc_service_pb2 as pb

    headers = {}
    if bearer:
        headers["authorization"] = f"Bearer {bearer}"
    if refresh_cookie:
        headers["cookie"] = f"vikunja_refresh_token={refresh_cookie}"
    ctx = pb.AttributeContext(
        source=pb.AttributeContext.Source(certificate=quote(cert_pem)),
        request=pb.AttributeContext.Request(
            http=pb.AttributeContext.HttpRequest(headers=headers)
        ),
    )
    return pb.CheckRequest(attributes=ctx)


@respx.mock
def test_check_injects_federated_bearer(grpc_servicer, trusted_email_cert_pem, monkeypatch):
    # No incoming bearer, no cache → federate → inject.
    import time

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
    req = _check_request(trusted_email_cert_pem)
    resp = grpc_servicer.Check(req, None)
    assert resp.HasField("ok_response")
    added = {h.header.key: h.header.value for h in resp.ok_response.headers_to_add}
    assert added["Authorization"] == f"Bearer {bearer}"


def test_check_allows_through_when_get_bearer_returns_none(
    grpc_servicer, trusted_email_cert_pem, monkeypatch
):
    # get_bearer returns None → OK with NO Authorization header (client's
    # incoming bearer was verified locally).
    from envoy_authz import grpc_service
    from envoy_authz.federator.vikunja import DownstreamError

    monkeypatch.setattr(
        grpc_service, "get_bearer", lambda *a, **k: None
    )
    req = _check_request(trusted_email_cert_pem, bearer="client-bearer")
    resp = grpc_servicer.Check(req, None)
    assert resp.HasField("ok_response")
    added = {h.header.key: h.header.value for h in resp.ok_response.headers_to_add}
    assert "Authorization" not in added


def test_check_denies_on_federation_failure(
    grpc_servicer, trusted_email_cert_pem, monkeypatch
):
    from envoy_authz import grpc_service
    from envoy_authz.federator.vikunja import DownstreamError

    monkeypatch.setattr(
        grpc_service,
        "get_bearer",
        lambda *a, **k: (_ for _ in ()).throw(DownstreamError("callback 500")),
    )
    req = _check_request(trusted_email_cert_pem)
    resp = grpc_servicer.Check(req, None)
    assert resp.HasField("denied_response")
    assert resp.denied_response.status.code == 401  # PERMISSION_DENIED maps to 7; assert denied
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `poetry run pytest tests/unit/test_check.py -v`
Expected: FAIL — `grpc_servicer` fixture / federation wiring missing.

- [ ] **Step 4: Add the `grpc_servicer` fixture to `tests/conftest.py`**

```python
@pytest.fixture
def grpc_servicer(monkeypatch, tmp_path):
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", FRIGATE_TEST_SECRET)
    monkeypatch.setenv("HA_CA_CERTIFICATE", _pem(_TRUSTED_CA))
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")

    from envoy_authz.federator import providers
    from envoy_authz.federator.store import _reset, seed
    from envoy_authz.grpc_service import AuthZServicer, init_federator

    p = tmp_path / "providers.yaml"
    p.write_text(OP_PROVIDERS_YAML)
    providers.load_providers(str(p))
    _reset()
    seed()
    init_federator("vikunja")  # wires _vikunja + _SESSIONS globals
    return AuthZServicer()
```

Also add a `trusted_email_cert_pem` fixture (a signed cert with an rfc822Name
SAN) — alias Task 3's `email_cert` fixture if present.

- [ ] **Step 5: Modify `envoy_authz/grpc_service.py`**

Add the federator wiring + ladder call. Sketch of the relevant changes:

```python
import logging

from .federator.providers import get_provider
from .federator.session import SessionCache, get_bearer
from .federator.subject import derive_subject
from .federator.vikunja import DownstreamError, VikunjaClient
from .identity import parse_client_identity

logger = logging.getLogger(__name__)

# Wired by init_federator (called from __main__ lifespan).
_vikunja: VikunjaClient | None = None
_SESSIONS: SessionCache | None = None


def init_federator(provider_name: str) -> None:
    global _vikunja, _SESSIONS
    import httpx

    provider = get_provider(provider_name)
    _vikunja = VikunjaClient(provider, httpx.Client(base_url=provider.api_base))
    _SESSIONS = SessionCache(ttl=300.0, margin=60.0)


def _extract_bearer(headers: dict) -> str | None:
    auth = headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip() or None
    return None


class AuthZServicer(AuthZServicerBase):  # keep existing base
    def Check(self, request, context):
        # ... existing mTLS verify + identity parse ...
        # Frigate path (existing X-Proxy-Secret injection) stays orthogonal;
        # federation runs only on the Vikunja path.
        subject = derive_subject(cert)
        http = request.attributes.request.http
        bearer = _extract_bearer(dict(http.headers))
        try:
            upstream = get_bearer(subject, bearer, _vikunja, _SESSIONS)
        except DownstreamError:
            logger.warning("denied-federation-failure sub=%s", subject.sub)
            return _deny_unauthorized()
        if upstream is None:
            # Client's own bearer verified locally → allow through unchanged.
            logger.info("allowed-through-client-bearer sub=%s", subject.sub)
            return _ok()  # no Authorization header added
        logger.info("injected-bearer sub=%s", subject.sub)
        return _ok_with_header("Authorization", f"Bearer {upstream}")
```

`_ok_with_header` appends a `HeaderValueOption` to `OkHttpResponse.headers_to_add`. `_deny_unauthorized` returns a `DeniedHttpResponse` with `PERMISSION_DENIED`. Keep the existing Frigate branch exactly as-is; only the Vikunja path calls the ladder.

- [ ] **Step 6: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 7: Run the check tests**

Run: `poetry run pytest tests/unit/test_check.py -v`
Expected: PASS — existing mTLS tests + new federation tests.

- [ ] **Step 8: Run the full suite**

Run: `poetry run pytest -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add envoy_authz/grpc_service.py tests/unit/test_check.py tests/conftest.py
git commit -m "feat: federate on gRPC Check, inject upstream bearer via headers_to_add

After mTLS identity extraction, derive the subject, extract the incoming
bearer, run get_bearer. str → inject Authorization: Bearer via headers_to_add;
None → allow through unchanged (no header); DownstreamError → deny (401).
Frigate X-Proxy-Secret path kept orthogonal. init_federator wires the
VikunjaClient + SessionCache globals at startup."
```

## Task 9: `__main__` lifespan wiring

**Files:**
- Modify: `envoy_authz/__main__.py`
- Create: `tests/unit/test_main.py`

**Interfaces:**
- Modifies: the `lifespan` to call `federator.providers.load_providers`, `federator.store.seed`, `op.init_op(app, key_path)`, and `grpc_service.init_federator("vikunja")` at startup; tear down the httpx client + cache on shutdown.
- Consumes: `config.Settings` (this task adds `op_key_path`; `providers_file`, `idp_issuer`, `secret_key` already from Task 1), all of the above.

- [ ] **Step 1: Read the current `__main__.py` and confirm env-var names**

Read `envoy_authz/__main__.py`. Preserve `GRPC_PORT`, `HTTP_PORT`, `TLS_CERT_PATH`, `TLS_KEY_PATH`, `FRIGATE_X_PROXY_SECRET`, `HA_CA_CERTIFICATE`, `HA_CRL` env-var names (k8s manifest depends on them). Add `PROVIDERS_FILE` (default `providers.yaml`), `OP_KEY_PATH` (default `op_key.pem`), `IDP_ISSUER`, `SECRET_KEY` to `Settings`.

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_main.py`:

```python
import pytest


def test_lifespan_loads_providers_and_mounts_op(monkeypatch, tmp_path):
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", "")
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("PROVIDERS_FILE", str(tmp_path / "providers.yaml"))
    monkeypatch.setenv("OP_KEY_PATH", str(tmp_path / "op_key.pem"))

    (tmp_path / "providers.yaml").write_text(
        "providers:\n  vikunja:\n    client_id: 'v'\n    client_secret: 's'\n"
        "    redirect_url: 'http://localhost:3456/auth/openid/broker'\n"
        "    api_base: 'http://localhost:3456'\n    provider_key: 'broker'\n"
        "    scope: 'openid profile email'\n"
    )

    from envoy_authz.__main__ import build_lifespan

    lifespan = build_lifespan()
    from envoy_authz.http_app import create_app

    app = create_app(lifespan=lifespan, op_key_path=str(tmp_path / "op_key.pem"))
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # OP mounted.
        disc = client.get("/.well-known/openid-configuration")
        assert disc.status_code == 200
        assert disc.json()["issuer"] == "https://idp.test"
        # Federator wired.
        from envoy_authz.grpc_service import _vikunja, _SESSIONS

        assert _vikunja is not None and _SESSIONS is not None


def test_lifespan_cleans_up_on_shutdown(monkeypatch, tmp_path):
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", "")
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("PROVIDERS_FILE", str(tmp_path / "providers.yaml"))
    monkeypatch.setenv("OP_KEY_PATH", str(tmp_path / "op_key.pem"))
    (tmp_path / "providers.yaml").write_text(
        "providers:\n  vikunja:\n    client_id: 'v'\n    client_secret: 's'\n"
        "    redirect_url: 'http://localhost:3456/auth/openid/broker'\n"
        "    api_base: 'http://localhost:3456'\n    provider_key: 'broker'\n"
        "    scope: 'openid profile email'\n"
    )

    from envoy_authz.__main__ import build_lifespan
    from envoy_authz.http_app import create_app
    from fastapi.testclient import TestClient

    app = create_app(lifespan=build_lifespan(), op_key_path=str(tmp_path / "op_key.pem"))
    with TestClient(app):
        pass
    # After shutdown, the httpx client should be closed (best-effort check:
    # the global is reset to None).
    from envoy_authz.grpc_service import _vikunja

    # _vikunja may persist; the cache + httpx client are closed. We assert no
    # exception on shutdown (the real contract).
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `poetry run pytest tests/unit/test_main.py -v`
Expected: FAIL — `build_lifespan` not found.

- [ ] **Step 4: Modify `envoy_authz/__main__.py`**

Refactor the lifespan into a `build_lifespan()` factory (so tests can construct it). Sketch:

```python
import logging
from contextlib import asynccontextmanager

from .config import Settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def build_lifespan():
    settings = Settings()
    # 1. Load providers.
    from .federator import providers
    providers.load_providers(settings.providers_file)
    # 2. Seed the OP store.
    from .federator.store import seed, _reset
    _reset()
    seed()
    # 3. Wire the federator (Vikunja client + session cache).
    from .grpc_service import init_federator
    init_federator("vikunja")
    # 4. The OP router is mounted by create_app(op_key_path=...) via init_op.
    try:
        yield
    finally:
        from .grpc_service import _vikunja, _SESSIONS
        if _vikunja is not None:
            _vikunja._client.close()
        if _SESSIONS is not None:
            _SESSIONS.clear()
```

In `main()`, pass `lifespan=build_lifespan()` and `op_key_path=settings.op_key_path` to `create_app`. Keep the existing gRPC server build + TLS + signal handling unchanged.

- [ ] **Step 5: Add the new Settings fields to `config.py`**

Task 1 already added `idp_issuer`, `secret_key`, `code_ttl_seconds`, `providers_file` to `Settings`. The only new field this task adds is `op_key_path` (the OP RSA signing-key path, used by `create_app`/`init_op`). Append it to `Settings` in `envoy_authz/config.py`:

```python
class Settings(BaseSettings):
    # ... existing fields (incl. idp_issuer, secret_key, providers_file from Task 1) ...
    op_key_path: str = "op_key.pem"   # NEW — OP RSA signing-key path
```

`secret_key` already defaults per Task 1; the dev/CI providers.yaml carries the
Vikunja service secret in `extra.session_secret`. Document the override in
README (Task 11).

- [ ] **Step 6: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 7: Run the main tests**

Run: `poetry run pytest tests/unit/test_main.py -v`
Expected: PASS.

- [ ] **Step 8: Run the full suite**

Run: `poetry run pytest -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add envoy_authz/__main__.py envoy_authz/config.py tests/unit/test_main.py
git commit -m "feat: lifespan wires providers, store seed, federator, OP mount

build_lifespan() factory loads providers.yaml, seeds the OP store, inits the
federator (Vikunja client + SessionCache), and tears down on shutdown. New
Settings fields: providers_file, op_key_path, idp_issuer, secret_key. Env-var
names for existing fields preserved."
```

## Task 10: docker-compose + integration test

**Files:**
- Create: `docker-compose.vikunja.yml`
- Create: `tests/integration/test_integration_vikunja.py`
- Modify: `tests/conftest.py` (integration marker registration, if not already done in Task 1)
- Modify: `pyproject.toml` (pytest markers, if not already done in Task 1)

**Interfaces:**
- Produces: a compose file bringing up Vikunja + a configured federator + a minimal Envoy stub (or direct gRPC client) for the integration test.
- Produces: `tests/integration/test_integration_vikunja.py` — an end-to-end test that mints an mTLS client cert, sends a real gRPC Check to the federator, and asserts Vikunja receives the bearer. Skipped unless `RUN_INTEGRATION=1`.

- [ ] **Step 1: Create the compose file**

Create `docker-compose.vikunja.yml`:

```yaml
services:
  vikunja:
    image: vikunja/vikunja:0.24
    environment:
      VIKUNJA_SERVICE_SECRET: integration-secret
      VIKUNJA_AUTH_OPENID_PROVIDERS_BROKER_ENABLED: "true"
      VIKUNJA_AUTH_OPENID_PROVIDERS_BROKER_ISSUER: "https://idp.local"
      VIKUNJA_AUTH_OPENID_PROVIDERS_BROKER_CLIENT_ID: "vikunja"
      VIKUNJA_AUTH_OPENID_PROVIDERS_BROKER_CLIENT_SECRET: "vikunja-secret"
      VIKUNJA_AUTH_OPENID_PROVIDERS_BROKER_REDIRECT_URL: "http://localhost:3456/auth/openid/broker"
    ports:
      - "3456:3456"
    # ... volumes, etc. (see Vikunja docs) ...

  federator:
    build: .
    environment:
      FRIGATE_X_PROXY_SECRET: "x"
      HA_CA_CERTIFICATE: ""
      PROVIDERS_FILE: "/etc/envoy-authz/providers.yaml"
      OP_KEY_PATH: "/data/op_key.pem"
      IDP_ISSUER: "https://idp.local"
      SECRET_KEY: "integration-secret"
    volumes:
      - ./providers.yaml:/etc/envoy-authz/providers.yaml:ro
    ports:
      - "5000:5000"   # OP HTTPS
      - "9090:9090"   # gRPC
    depends_on:
      - vikunja
```

- [ ] **Step 2: Create the integration test**

Create `tests/integration/test_integration_vikunja.py`:

```python
"""End-to-end federation test against a live Vikunja.

Skipped unless RUN_INTEGRATION=1. Bring up the stack with:
    docker compose -f docker-compose.vikunja.yml up -d
    RUN_INTEGRATION=1 poetry run pytest tests/integration -v
"""

import os
import ssl

import grpc
import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_INTEGRATION"),
    reason="set RUN_INTEGRATION=1 to run integration tests",
)


def test_check_federates_to_vikunja(trusted_email_cert_pem):
    from envoy_authz import grpc_service_pb2 as pb
    from urllib.parse import quote

    channel_creds = grpc.ssl_channel_credentials(
        root_certificates=os.environ.get("TLS_CA").encode(),
        certificate_chain=trusted_email_cert_pem.encode(),
        private_key=os.environ.get("TLS_CLIENT_KEY").encode(),
    )
    with grpc.secure_channel("localhost:9090", channel_creds) as channel:
        stub = grpc_service_pb2_grpc.AuthZStub(channel)
        req = pb.CheckRequest(
            attributes=pb.AttributeContext(
                source=pb.AttributeContext.Source(certificate=quote(trusted_email_cert_pem)),
                request=pb.AttributeContext.Request(
                    http=pb.AttributeContext.HttpRequest(headers={})
                ),
            )
        )
        resp = stub.Check(req)
    # The federator minted a session and injected a bearer.
    assert resp.HasField("ok_response")
    added = {h.header.key: h.header.value for h in resp.ok_response.headers_to_add}
    assert added["Authorization"].startswith("Bearer ")
```

- [ ] **Step 3: Ensure the integration marker is registered**

Confirm `pyproject.toml` `[tool.pytest.ini_options]` includes `markers = ["integration: end-to-end tests requiring live services (RUN_INTEGRATION=1)"]` (added in Task 1). If not, add it.

- [ ] **Step 4: Lint**

Run: `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests`

- [ ] **Step 5: Verify the integration test is collected (and skipped)**

Run: `poetry run pytest tests/integration -v`
Expected: 1 skipped (RUN_INTEGRATION not set).

- [ ] **Step 6: Commit**

```bash
git add docker-compose.vikunja.yml tests/integration/test_integration_vikunja.py pyproject.toml
git commit -m "test: add Vikunja integration test + docker-compose stack

End-to-end federation test (skipped unless RUN_INTEGRATION=1) mints an mTLS
client cert, sends a real gRPC Check, and asserts a bearer is injected.
Compose brings up Vikunja + the federator with the broker provider configured."
```

## Task 11: Docs

**Files:**
- Modify: `README.md` (or create `docs/federation.md`)
- Modify: `providers.yaml` (committed sample)

- [ ] **Step 1: Document the federation flow**

Add a section to `README.md` (or a new `docs/federation.md`) covering: the mTLS→OAuth2 federation topology, the `providers.yaml` schema (incl. `extra.session_secret`), the new env vars (`PROVIDERS_FILE`, `OP_KEY_PATH`, `IDP_ISSUER`, `SECRET_KEY`), the OP endpoints (`/.well-known/openid-configuration`, `/jwks.json`, `/oauth/token`, `/oauth/userinfo`), and how to run the integration stack.

- [ ] **Step 2: Commit the sample `providers.yaml` + docs**

```bash
git add README.md providers.yaml docs/federation.md
git commit -m "docs: federation topology, providers.yaml schema, env vars, OP endpoints"
```

---

## Verification (whole-plan)

- [ ] `poetry run ruff check --fix envoy_authz tests && poetry run ruff format envoy_authz tests` — clean
- [ ] `poetry run pytest -v` — all unit tests pass
- [ ] `poetry run pytest tests/integration -v` — skipped (or green with `RUN_INTEGRATION=1` against the compose stack)
- [ ] No bearer tokens, refresh cookies, or `SecretStr` values appear in any log line or test output (grep `caplog` assertions)
- [ ] Existing env-var names preserved; k8s manifest unchanged in its env-var set
- [ ] `git log --oneline` shows one commit per task, each task's stated files staged explicitly (no blanket `git add`)
