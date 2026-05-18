# Integration Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pytest-based gRPC integration test suite that exercises every authorization path in `envoy_authz.app.AuthorizationService.Check`.

**Architecture:** A `tests/conftest.py` generates an ephemeral PKI (two CAs, server cert, three client certs) at module load, sets `HA_CA_CERTIFICATE` and `FRIGATE_X_PROXY_SECRET` env vars *before* importing `envoy_authz.app`, and starts a real `grpc.server` with TLS bound to an OS-allocated port. Tests in `tests/integration/test_check.py` build `CheckRequest` protobuf messages and assert on real server responses.

**Tech Stack:** Python 3.12+, pytest, grpcio, cryptography (for test cert authoring), pyOpenSSL (production verification path).

---

## File Structure

**New files**
- `tests/__init__.py` — empty marker
- `tests/integration/__init__.py` — empty marker
- `tests/conftest.py` — PKI generation, env-var prep, gRPC server/stub fixtures, request builder fixture
- `tests/integration/test_setup.py` — single sanity test that env-var wiring works
- `tests/integration/test_check.py` — the nine scenario tests

**Modified files**
- `pyproject.toml` — add `pytest` and `cryptography` to the `dev` group; add `[tool.pytest.ini_options]`
- `.woodpecker.yaml` — add a `test` step between `lint` and `build-and-push`

---

## Task 1: Add dev dependencies and pytest config

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add pytest and cryptography to the dev dependency group**

Edit `pyproject.toml`. The current `[dependency-groups]` block is:

```toml
[dependency-groups]
dev = [
    "ruff (>=0.14.5,<0.15.0)"
]
```

Replace it with:

```toml
[dependency-groups]
dev = [
    "ruff (>=0.14.5,<0.15.0)",
    "pytest (>=8.3.0,<9.0.0)",
    "cryptography (>=44.0.0,<46.0.0)"
]
```

- [ ] **Step 2: Add pytest configuration**

Append the following to the end of `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra -q"
```

- [ ] **Step 3: Install dev dependencies**

Run: `poetry install --no-root --with dev`
Expected: exit 0; lockfile updated; pytest and cryptography appear in `.venv`.

- [ ] **Step 4: Verify pytest is callable**

Run: `poetry run pytest --version`
Expected: prints `pytest 8.x.y` and exits 0.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml poetry.lock
git commit -m "chore: add pytest and cryptography to dev dependencies"
```

---

## Task 2: Set up conftest with PKI generation and env-var prep

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/integration/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/integration/test_setup.py`

This task does NOT add the gRPC server fixture yet. It only proves the env-var-before-import wiring is solid, by importing `envoy_authz.app` and checking the module-level constants.

- [ ] **Step 1: Create the empty `__init__.py` files**

Create `tests/__init__.py` and `tests/integration/__init__.py` as empty files:

```bash
mkdir -p tests/integration
: > tests/__init__.py
: > tests/integration/__init__.py
```

- [ ] **Step 2: Write the failing setup test**

Create `tests/integration/test_setup.py`:

```python
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
```

- [ ] **Step 3: Run it to confirm it fails before conftest exists**

Run: `poetry run pytest tests/integration/test_setup.py -v`
Expected: ERROR collecting — `KeyError: 'FRIGATE_X_PROXY_SECRET'` from `app.py` import, because no conftest has set the env vars yet.

- [ ] **Step 4: Create conftest.py with PKI generation and env-var prep**

Create `tests/conftest.py`:

```python
"""Test fixtures for envoy_authz integration tests.

This module's top-level code runs at pytest conftest load time, which
happens before any test module is imported. It generates an ephemeral
PKI, sets the env vars that `envoy_authz.app` reads at import time, and
*then* imports the app so its module-level globals (HA_CA_STORE,
FRIGATE_X_PROXY_SECRET) are built from the test values.
"""

import datetime
import os
import socket
import urllib.parse
from concurrent import futures
from contextlib import closing

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


FRIGATE_TEST_SECRET = "test-frigate-secret-abc123"


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _generate_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _build_signed_cert(
    common_name: str,
    issuer_key: rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _generate_key()
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )
    return key, cert


def _build_server_cert(
    common_name: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Self-signed server cert with a SubjectAltName for TLS validation."""
    key = _generate_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _pem_bytes(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---- Generate the PKI bundle at conftest load (before app import) ----

_TRUSTED_CA_KEY, _TRUSTED_CA = _build_ca("test-trusted-ca")
_UNTRUSTED_CA_KEY, _UNTRUSTED_CA = _build_ca("test-untrusted-ca")
_SERVER_KEY, _SERVER_CERT = _build_server_cert("localhost")

_TRUSTED_CLIENT_KEY, _TRUSTED_CLIENT_CERT = _build_signed_cert(
    "trusted-client", _TRUSTED_CA_KEY, _TRUSTED_CA
)
_UNTRUSTED_CLIENT_KEY, _UNTRUSTED_CLIENT_CERT = _build_signed_cert(
    "untrusted-client", _UNTRUSTED_CA_KEY, _UNTRUSTED_CA
)
_SELF_SIGNED_CLIENT_KEY, _SELF_SIGNED_CLIENT_CERT = _build_ca(
    "self-signed-client"
)

# Set env vars BEFORE importing the app module
os.environ["HA_CA_CERTIFICATE"] = _pem(_TRUSTED_CA)
os.environ["FRIGATE_X_PROXY_SECRET"] = FRIGATE_TEST_SECRET

# Now safe to import — triggers the global HA_CA_STORE build
from envoy_authz import app  # noqa: E402
```

- [ ] **Step 5: Run the setup test, expect PASS**

Run: `poetry run pytest tests/integration/test_setup.py -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add tests/ pyproject.toml
git commit -m "test: bootstrap pytest with ephemeral PKI and env-var prep"
```

---

## Task 3: Add gRPC server and client fixtures plus the first scenario test

**Files:**
- Modify: `tests/conftest.py`
- Create: `tests/integration/test_check.py`

- [ ] **Step 1: Add the failing first test**

Create `tests/integration/test_check.py`:

```python
"""Integration tests for AuthorizationService.Check over real gRPC + TLS."""

from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2


FRIGATE_HOST = "frigate.apps.somemissing.info"


def _header_value(response, key: str) -> str | None:
    for h in response.ok_response.headers:
        if h.header.key == key:
            return h.header.value
    return None


def test_frigate_metrics_no_cert_allowed(stub, check_request):
    response = stub.Check(
        check_request(host=FRIGATE_HOST, path="/api/metrics")
    )

    assert response.status.code == code_pb2.OK
    assert _header_value(response, "X-Proxy-Secret") is None
```

- [ ] **Step 2: Run it to confirm it fails (no fixtures yet)**

Run: `poetry run pytest tests/integration/test_check.py -v`
Expected: ERROR — `fixture 'stub' not found` (and `check_request`).

- [ ] **Step 3: Append gRPC server, stub, and helper fixtures to conftest.py**

Append the following to `tests/conftest.py`:

```python
from envoy.service.auth.v3 import (  # noqa: E402
    external_auth_pb2,
    external_auth_pb2_grpc,
)


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def grpc_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        app.AuthorizationService(), server
    )
    credentials = grpc.ssl_server_credentials(
        [(_pem_key(_SERVER_KEY), _pem_bytes(_SERVER_CERT))]
    )
    port = server.add_secure_port("[::]:0", credentials)
    server.start()
    try:
        yield port
    finally:
        server.stop(grace=None)


@pytest.fixture
def stub(grpc_server):
    creds = grpc.ssl_channel_credentials(
        root_certificates=_pem_bytes(_SERVER_CERT)
    )
    options = (("grpc.ssl_target_name_override", "localhost"),)
    channel = grpc.secure_channel(
        f"localhost:{grpc_server}", creds, options=options
    )
    try:
        yield external_auth_pb2_grpc.AuthorizationStub(channel)
    finally:
        channel.close()


@pytest.fixture(scope="session")
def check_request():
    """Returns a builder for `CheckRequest` messages."""

    def _build(*, host: str, path: str, client_cert_pem: str | None = None):
        request = external_auth_pb2.CheckRequest()
        request.attributes.request.http.host = host
        request.attributes.request.http.path = path
        if client_cert_pem is not None:
            # Envoy URL-encodes the cert PEM in source.certificate
            request.attributes.source.certificate = urllib.parse.quote(
                client_cert_pem
            )
        return request

    return _build


@pytest.fixture(scope="session")
def trusted_client_cert_pem() -> str:
    return _pem(_TRUSTED_CLIENT_CERT)


@pytest.fixture(scope="session")
def untrusted_client_cert_pem() -> str:
    return _pem(_UNTRUSTED_CLIENT_CERT)


@pytest.fixture(scope="session")
def self_signed_client_cert_pem() -> str:
    return _pem(_SELF_SIGNED_CLIENT_CERT)


@pytest.fixture(scope="session")
def frigate_secret() -> str:
    return FRIGATE_TEST_SECRET
```

The `noqa: E402` on the envoy_service import is intentional — those imports must come after the env-var assignment block.

- [ ] **Step 4: Run the test, expect PASS**

Run: `poetry run pytest tests/integration/test_check.py -v`
Expected: 1 passed.

- [ ] **Step 5: Run the full suite to confirm nothing else broke**

Run: `poetry run pytest -v`
Expected: 4 passed (3 setup + 1 check).

- [ ] **Step 6: Commit**

```bash
git add tests/conftest.py tests/integration/test_check.py
git commit -m "test: add gRPC server and client fixtures plus first allow-path test"
```

---

## Task 4: Add remaining allow-path tests

**Files:**
- Modify: `tests/integration/test_check.py`

- [ ] **Step 1: Append the two remaining allow-path tests**

Append to `tests/integration/test_check.py`:

```python
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
```

- [ ] **Step 2: Run, expect three allow-path tests to pass**

Run: `poetry run pytest tests/integration/test_check.py -v`
Expected: 3 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_check.py
git commit -m "test: cover remaining allow-path scenarios"
```

---

## Task 5: Add deny-path tests

**Files:**
- Modify: `tests/integration/test_check.py`

- [ ] **Step 1: Append the shared deny-path helper and all six deny tests**

Append to `tests/integration/test_check.py`:

```python
def _assert_denied(response) -> None:
    assert response.status.code == code_pb2.PERMISSION_DENIED
    assert (
        response.denied_response.status.code
        == http_status_pb2.StatusCode.Forbidden
    )
    assert response.denied_response.body == '{"error": "Unauthorized"}'


def test_no_cert_on_non_metrics_denied(stub, check_request):
    response = stub.Check(
        check_request(host=FRIGATE_HOST, path="/api/events")
    )
    _assert_denied(response)


def test_wrong_path_on_frigate_without_cert_denied(stub, check_request):
    response = stub.Check(
        check_request(host=FRIGATE_HOST, path="/api/metrics_extra")
    )
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
```

- [ ] **Step 2: Run the full suite**

Run: `poetry run pytest -v`
Expected: 12 passed (3 setup + 9 check scenarios).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_check.py
git commit -m "test: cover deny-path scenarios"
```

---

## Task 6: Wire pytest into Woodpecker CI

**Files:**
- Modify: `.woodpecker.yaml`

- [ ] **Step 1: Add a `test` step between `lint` and `build-and-push`**

In `.woodpecker.yaml`, the current `steps:` block looks like:

```yaml
steps:
  lint:
    # renovate: datasource=docker depName=python
    image: python:3.14-slim
    commands:
      - pip install poetry==2.2.1
      - poetry install --no-root --with dev
      - poetry run ruff check .

  build-and-push:
    ...
```

Insert a `test` step right after `lint`:

```yaml
  test:
    # renovate: datasource=docker depName=python
    image: python:3.14-slim
    commands:
      - pip install poetry==2.2.1
      - poetry install --no-root --with dev
      - poetry run pytest
```

- [ ] **Step 2: Validate yaml syntax**

Run: `poetry run python -c "import yaml; yaml.safe_load(open('.woodpecker.yaml'))"`
Expected: exit 0; no error.

- [ ] **Step 3: Commit**

```bash
git add .woodpecker.yaml
git commit -m "ci: run pytest in woodpecker pipeline"
```

---

## Final verification

After all tasks: run `poetry run pytest -v` once more. Expected: 12 passed, 0 failed, 0 errors.
