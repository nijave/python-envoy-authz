# In-process HTTPS server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run an async FastAPI/Uvicorn HTTPS server in the same process as the existing synchronous gRPC `ext_authz` server, sharing the read-only `Config`, terminating TLS in-process with the same certs on a different port.

**Architecture:** Split the single `envoy_authz/app.py` into a small package (`config`, `grpc_service`, `http_app`, `__main__`). `__main__` runs Uvicorn on the main thread (owns SIGTERM/SIGINT) and manages the gRPC server via a FastAPI `lifespan`: startup builds `Config`, starts gRPC (non-blocking, background worker threads) and sets health SERVING; shutdown flips health NOT_SERVING and drains gRPC with grace. Only the read-only `Config` is shared; no mutable state this step.

**Tech Stack:** Python ≥3.12, gRPC (grpcio), FastAPI + `uvicorn[standard]` (uvloop + httptools), pyOpenSSL/cryptography, poetry, pytest, ruff.

## ⚠️ Pre-implementation reconciliation

This plan was authored on a branch cut from `main` **before** the `feat/client-cert-identity` work merged. That work is expected to land in `main` first, so at implementation time the tree will differ from the snapshots below. Before starting, reconcile:

- **pydantic** will already be a dependency — do **not** re-add it. `fastapi` still must be added (Task 2); it depends on pydantic, which is fine.
- **`tests/unit/`** (with `__init__.py` and identity tests) will already exist — in Task 2 Step 3, create `tests/unit/__init__.py` only if absent; always add `tests/unit/test_http_app.py`.
- **`envoy_authz/identity.py`** will already exist — the split leaves it untouched (it's already a focused module). If the merged `app.py` imports it, carry that import into whichever new module uses it.
- **`app.py` contents will differ** — the merged version likely returns a client identity from `verify_client_cert` and threads `ClientIdentity` through `Check`. Task 1 shows the *pre-merge* code; **move the then-current contents verbatim** into `config.py` / `grpc_service.py`, preserving whatever behavior main has. The module boundaries (config vs servicer vs http) and the `register_services` extraction still apply regardless of the identity details.
- After reconciling, the safety net is unchanged: the existing suite (now including the merged identity tests) must stay green through Task 1.

## Global Constraints

- Python `>=3.12`; dependency manager is **poetry** (edit `pyproject.toml`, regenerate `poetry.lock`).
- gRPC stays on port **5000**; HTTP listens on **5001** (override via `HTTP_PORT`, default `5001`).
- TLS terminated in-process from `/var/lib/tls/tls.crt` + `/var/lib/tls/tls.key` (override via `TLS_CERT_PATH` / `TLS_KEY_PATH`).
- Single process only — no multi-worker/fork servers (no `gunicorn`, no `uvicorn --workers N`).
- Existing gRPC `ext_authz` behavior (the `Check` RPC, cert verification, CRL, frigate header) is unchanged — the split is a pure refactor with the existing test suite as the safety net.
- Lint/format with `ruff` (dev dependency already present); run `poetry run ruff check` before each commit.
- Stage explicit file paths in every commit; never `git add -A`.

---

### Task 1: Split `app.py` into `config.py` + `grpc_service.py` (behavior-preserving refactor)

Extract the config/PKI helpers and the gRPC servicer into focused modules, add package init with shared JSON logging, keep `app.py` runnable (it imports from the new modules), and repoint the test suite. This is a refactor: the existing test suite is the safety net — no new failing test.

**Files:**
- Create: `envoy_authz/__init__.py`
- Create: `envoy_authz/config.py`
- Create: `envoy_authz/grpc_service.py`
- Modify: `envoy_authz/app.py` (import from new modules; keep `__main__`)
- Modify: `tests/conftest.py` (import from new modules; use `register_services`)

**Interfaces:**
- Produces:
  - `envoy_authz.config.Config` (dataclass: `frigate_proxy_secret: str`, `ha_ca_store: OpenSSL.crypto.X509Store`)
  - `envoy_authz.config.configure_crl(store, crl_pem) -> bool`
  - `envoy_authz.config.build_store(ca_cert_pem: str, crl_pem: str | None = None) -> crypto.X509Store`
  - `envoy_authz.config.load_config() -> Config`
  - `envoy_authz.config.verify_client_cert(cert_pem: str, store: crypto.X509Store) -> bool`
  - `envoy_authz.grpc_service.FRIGATE_HOST: str`
  - `envoy_authz.grpc_service.AuthorizationService(config: Config)`
  - `envoy_authz.grpc_service.register_services(server: grpc.Server, config: Config) -> grpc_health.v1.health.HealthServicer`

- [ ] **Step 1: Create `envoy_authz/__init__.py` with shared JSON logging**

```python
"""envoy_authz package.

Configures process-wide JSON logging on import so both the gRPC and HTTP
entrypoints emit consistent structured logs.
"""

import logging
import sys

from pythonjsonlogger import json as jsonlogger

_handler = logging.StreamHandler(stream=sys.stdout)
_handler.setFormatter(jsonlogger.JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[_handler])
```

- [ ] **Step 2: Create `envoy_authz/config.py`**

```python
import datetime
import logging
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto

logger = logging.getLogger(__name__)


@dataclass
class Config:
    frigate_proxy_secret: str
    # Shared across the gRPC thread pool; must not be mutated after the
    # server starts (concurrent reads during cert verification are safe).
    ha_ca_store: crypto.X509Store


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
    return Config(
        frigate_proxy_secret=os.environ["FRIGATE_X_PROXY_SECRET"],
        ha_ca_store=build_store(
            os.environ["HA_CA_CERTIFICATE"],
            os.environ.get("HA_CRL"),
        ),
    )


def verify_client_cert(cert_pem: str, store: crypto.X509Store) -> bool:
    """Verify client certificate against CA."""
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())
        crypto.X509StoreContext(store, cert).verify_certificate()

        eku = cert.to_cryptography().extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        )
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
            return False

        return True
    except Exception:
        logger.exception("Client cert verification failed")
        return False
```

- [ ] **Step 3: Create `envoy_authz/grpc_service.py`**

```python
import logging
import urllib.parse

import grpc
from grpc_health.v1 import health, health_pb2_grpc
from envoy.config.core.v3.base_pb2 import HeaderValueOption, HeaderValue
from envoy.service.auth.v3 import external_auth_pb2
from envoy.service.auth.v3 import external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2, status_pb2

from .config import Config, verify_client_cert

logger = logging.getLogger(__name__)

FRIGATE_HOST = "frigate.apps.somemissing.info"


class AuthorizationService(external_auth_pb2_grpc.AuthorizationServicer):
    """Simple Envoy External Authorization Service"""

    def __init__(self, config: Config):
        self._config = config

    def Check(self, request, context):
        """Entry point called by Envoy to authorize a request"""

        headers = dict(request.attributes.request.http.headers)
        path = request.attributes.request.http.path

        logger.info(
            "Request received",
            extra={
                "host": request.attributes.request.http.host,
                "path": path,
                "principal": request.attributes.source.principal,
            },
        )
        logger.debug("Headers: %s", headers)

        allowed = (
            request.attributes.request.http.host == FRIGATE_HOST
            and path == "/api/metrics"
        ) or (
            verify_client_cert(
                urllib.parse.unquote(request.attributes.source.certificate),
                self._config.ha_ca_store,
            )
        )

        if allowed:
            logger.info("✓ Authorized")

            return_headers: list[HeaderValueOption] = []

            if request.attributes.request.http.host == FRIGATE_HOST:
                return_headers.append(
                    HeaderValueOption(
                        header=HeaderValue(
                            key="X-Proxy-Secret",
                            value=self._config.frigate_proxy_secret,
                        ),
                    )
                )

            return external_auth_pb2.CheckResponse(
                status=status_pb2.Status(code=code_pb2.OK),
                ok_response=external_auth_pb2.OkHttpResponse(
                    headers=return_headers,
                ),
            )
        else:
            logger.info("✗ Denied")
            return external_auth_pb2.CheckResponse(
                status=status_pb2.Status(code=code_pb2.PERMISSION_DENIED),
                denied_response=external_auth_pb2.DeniedHttpResponse(
                    status=http_status_pb2.HttpStatus(
                        code=http_status_pb2.StatusCode.Forbidden
                    ),
                    body='{"error": "Unauthorized"}',
                ),
            )


def register_services(server: grpc.Server, config: Config) -> health.HealthServicer:
    """Register the authz + health servicers on `server`.

    Returns the health servicer so the caller can flip SERVING/NOT_SERVING
    around start/stop.
    """
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        AuthorizationService(config), server
    )
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    return health_servicer
```

- [ ] **Step 4: Replace `envoy_authz/app.py` body with imports from the new modules (keep `__main__`)**

Overwrite `envoy_authz/app.py` with:

```python
import logging
import signal
from concurrent import futures

import grpc
from grpc_health.v1 import health_pb2

from .config import (  # noqa: F401  (re-exported for tests/back-compat)
    Config,
    build_store,
    configure_crl,
    load_config,
    verify_client_cert,
)
from .grpc_service import (  # noqa: F401
    FRIGATE_HOST,
    AuthorizationService,
    register_services,
)

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    config = load_config()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_servicer = register_services(server, config)

    with open("/var/lib/tls/tls.key", "rb") as f:
        private_key = f.read()
    with open("/var/lib/tls/tls.crt", "rb") as f:
        certificate_chain = f.read()

    server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
    server.add_secure_port("[::]:5000", server_credentials)

    logger.info("Starting secure gRPC server on port 5000...")
    server.start()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)

    def _shutdown(signum, _frame):
        logger.info("Received signal %s, draining...", signum)
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        server.stop(grace=10)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server.wait_for_termination()
```

Note: `app.py` is deleted in Task 3 once `__main__.py` replaces it; this step keeps it working so the suite stays green mid-refactor.

- [ ] **Step 5: Update `tests/conftest.py` imports and use `register_services`**

Change the import block near the top of `tests/conftest.py` from:

```python
from envoy_authz import app
from envoy_authz.app import AuthorizationService, Config
```

to:

```python
from envoy_authz.config import Config, build_store
from envoy_authz.grpc_service import AuthorizationService, register_services
```

In the `ha_config` fixture, replace `app.build_store(` with `build_store(`.

In the `grpc_server` fixture, replace the two manual `add_*_to_server(...)` registration lines:

```python
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        AuthorizationService(ha_config), server
    )
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
```

with:

```python
    health_servicer = register_services(server, ha_config)
```

(The `AuthorizationService` import is still used elsewhere in the fixtures/tests; keep it. The `health`/`health_pb2_grpc` imports remain used for `health_servicer.set(...)` and the health stub.)

- [ ] **Step 6: Run the full suite to verify the refactor is green**

Run: `poetry run pytest -q`
Expected: PASS — same test count as before the refactor (integration `test_check`, `test_health`, `test_setup` all pass).

- [ ] **Step 7: Lint**

Run: `poetry run ruff check envoy_authz tests`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add envoy_authz/__init__.py envoy_authz/config.py envoy_authz/grpc_service.py envoy_authz/app.py tests/conftest.py
git commit -m "refactor: split app.py into config + grpc_service package modules"
```

---

### Task 2: Add FastAPI/Uvicorn deps and the `http_app` factory with `/healthz`

**Files:**
- Modify: `pyproject.toml` (add `fastapi`, `uvicorn[standard]` to deps; `httpx` to dev group)
- Create: `envoy_authz/http_app.py`
- Create: `tests/unit/__init__.py`
- Create: `tests/unit/test_http_app.py`

**Interfaces:**
- Consumes: nothing from Task 1 (decoupled from gRPC).
- Produces: `envoy_authz.http_app.create_app(lifespan=None) -> fastapi.FastAPI` exposing `GET /healthz -> {"status": "ok"}` with HTTP 200.

- [ ] **Step 1: Add dependencies**

Add to the `dependencies` array in `pyproject.toml`:

```toml
    "fastapi (>=0.115.0,<1.0.0)",
    "uvicorn[standard] (>=0.30.0,<1.0.0)"
```

Add to the `[dependency-groups]` `dev` array (TestClient needs httpx):

```toml
    "httpx (>=0.27.0,<1.0.0)"
```

- [ ] **Step 2: Install and lock**

Run: `poetry lock && poetry install`
Expected: resolves and installs fastapi, uvicorn (+ uvloop, httptools), httpx.

- [ ] **Step 3: Write the failing test**

Create `tests/unit/__init__.py` (empty file — skip if it already exists post-merge), then `tests/unit/test_http_app.py`:

```python
from fastapi.testclient import TestClient

from envoy_authz.http_app import create_app


def test_healthz_returns_ok():
    client = TestClient(create_app())
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_app_returns_distinct_instances():
    assert create_app() is not create_app()
```

- [ ] **Step 4: Run test to verify it fails**

Run: `poetry run pytest tests/unit/test_http_app.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'envoy_authz.http_app'`.

- [ ] **Step 5: Create `envoy_authz/http_app.py`**

```python
"""FastAPI application factory for the in-process HTTPS server.

Decoupled from the gRPC side: the caller (``__main__``) supplies a
``lifespan`` that owns the gRPC server. Routes that need shared config read
it from ``request.app.state`` (populated by that lifespan).
"""

from fastapi import FastAPI


def create_app(lifespan=None) -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app
```

- [ ] **Step 6: Run test to verify it passes**

Run: `poetry run pytest tests/unit/test_http_app.py -v`
Expected: PASS (both tests).

- [ ] **Step 7: Lint**

Run: `poetry run ruff check envoy_authz tests`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml poetry.lock envoy_authz/http_app.py tests/unit/__init__.py tests/unit/test_http_app.py
git commit -m "feat: add FastAPI http_app factory with /healthz"
```

---

### Task 3: Wire gRPC + Uvicorn in `__main__.py`; delete `app.py`; update Dockerfile

**Files:**
- Create: `envoy_authz/__main__.py`
- Delete: `envoy_authz/app.py`
- Modify: `Dockerfile` (`CMD` → `python -m envoy_authz`; `EXPOSE 5000 5001`)

**Interfaces:**
- Consumes: `envoy_authz.config.load_config`, `envoy_authz.grpc_service.register_services`, `envoy_authz.http_app.create_app`.
- Produces: `python -m envoy_authz` runs both servers in one process; `envoy_authz.__main__.build_grpc_server(config) -> (grpc.Server, HealthServicer)`; `envoy_authz.__main__.lifespan` (FastAPI lifespan managing the gRPC server).

- [ ] **Step 1: Create `envoy_authz/__main__.py`**

```python
import contextlib
import logging
import os
from concurrent import futures

import grpc
import uvicorn
from grpc_health.v1 import health_pb2

from .config import load_config
from .grpc_service import register_services
from .http_app import create_app

logger = logging.getLogger(__name__)

GRPC_PORT = int(os.environ.get("GRPC_PORT", "5000"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "5001"))
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/var/lib/tls/tls.crt")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/var/lib/tls/tls.key")


def build_grpc_server(config):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_servicer = register_services(server, config)

    with open(TLS_KEY_PATH, "rb") as f:
        private_key = f.read()
    with open(TLS_CERT_PATH, "rb") as f:
        certificate_chain = f.read()

    credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
    server.add_secure_port(f"[::]:{GRPC_PORT}", credentials)
    return server, health_servicer


@contextlib.asynccontextmanager
async def lifespan(app):
    config = load_config()
    server, health_servicer = build_grpc_server(config)
    server.start()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    logger.info("Secure gRPC server started on port %s", GRPC_PORT)
    app.state.config = config
    try:
        yield
    finally:
        logger.info("Draining gRPC server...")
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        server.stop(grace=10)


def main():
    app = create_app(lifespan=lifespan)
    logger.info("Starting HTTPS server on port %s", HTTP_PORT)
    uvicorn.run(
        app,
        host="::",
        port=HTTP_PORT,
        ssl_certfile=TLS_CERT_PATH,
        ssl_keyfile=TLS_KEY_PATH,
        log_config=None,
    )


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Delete the now-obsolete `app.py`**

Run: `git rm envoy_authz/app.py`
Expected: file removed. (No test imports it — Task 1 repointed `conftest.py`.)

- [ ] **Step 3: Confirm the existing suite still passes without `app.py`**

Run: `poetry run pytest -q`
Expected: PASS — unit `test_http_app` + all integration tests green (proves the gRPC path still works via `register_services`).

- [ ] **Step 4: Local end-to-end smoke test (real HTTPS + graceful shutdown)**

Generate a throwaway self-signed cert into the scratchpad and run the process:

```bash
SCRATCH="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$SCRATCH/tls.key" -out "$SCRATCH/tls.crt" \
  -subj "/CN=localhost" -days 1
TLS_CERT_PATH="$SCRATCH/tls.crt" TLS_KEY_PATH="$SCRATCH/tls.key" \
  HTTP_PORT=5001 GRPC_PORT=5000 \
  FRIGATE_X_PROXY_SECRET=smoke-secret \
  HA_CA_CERTIFICATE="$(cat "$SCRATCH/tls.crt")" \
  poetry run python -m envoy_authz &
APP_PID=$!
sleep 3
curl -sk https://localhost:5001/healthz
echo
kill -TERM "$APP_PID"; wait "$APP_PID" 2>/dev/null
rm -rf "$SCRATCH"
```

Expected: `curl` prints `{"status":"ok"}`; logs show "Secure gRPC server started on port 5000", "Starting HTTPS server on port 5001", and on SIGTERM "Draining gRPC server...".

- [ ] **Step 5: Update the Dockerfile**

In `Dockerfile`, change:

```dockerfile
EXPOSE 5000
CMD ["/root/.local/bin/poetry", "run", "python3", "envoy_authz/app.py"]
```

to:

```dockerfile
EXPOSE 5000 5001
CMD ["/root/.local/bin/poetry", "run", "python3", "-m", "envoy_authz"]
```

- [ ] **Step 6: Lint**

Run: `poetry run ruff check envoy_authz tests`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add envoy_authz/__main__.py Dockerfile
git rm envoy_authz/app.py
git commit -m "feat: run HTTPS server alongside gRPC via python -m envoy_authz"
```

---

### Task 4: Expose the HTTP port in the Kubernetes manifest

**Files:**
- Modify: `k8s.yaml` (add `http`/5001 container port + HTTPS readiness/liveness probe on `/healthz`; add Service port)

**Interfaces:**
- Consumes: `GET /healthz` on `5001` (from Task 2/3).
- Produces: cluster exposure of the HTTP surface.

- [ ] **Step 1: Add the HTTP container port and probe**

In the `python-envoy-authz` Deployment container spec, extend the `ports:` list (which currently has only `grpc`/5000) with:

```yaml
          - name: http
            protocol: TCP
            containerPort: 5001
```

Add HTTP probes alongside the existing gRPC `livenessProbe`/`readinessProbe` (keep the gRPC probes as-is) by adding a startup-independent HTTP readiness probe:

```yaml
        startupProbe:
          httpGet:
            path: /healthz
            port: 5001
            scheme: HTTPS
          initialDelaySeconds: 3
          periodSeconds: 5
          failureThreshold: 6
```

(`scheme: HTTPS` makes the kubelet skip cert verification for the probe, matching the existing `-tls-no-verify` gRPC probes. The existing gRPC liveness/readiness probes remain the primary signal; this adds coverage that the HTTP listener is up.)

- [ ] **Step 2: Add the Service port**

In the `python-envoy-authz` Service `spec.ports`, alongside the existing `https`/443→5000 entry, add:

```yaml
    - name: http
      port: 5001
      protocol: TCP
      targetPort: 5001
```

- [ ] **Step 3: Validate the manifest**

Run: `python -c "import yaml,sys; list(yaml.safe_load_all(open('k8s.yaml'))); print('k8s.yaml parses')"`
Expected: `k8s.yaml parses` (no YAML errors). If `kubectl` is available: `kubectl apply --dry-run=client -f k8s.yaml` should report the resources as valid.

- [ ] **Step 4: Commit**

```bash
git add k8s.yaml
git commit -m "feat: expose HTTP /healthz port 5001 in k8s manifest"
```

---

## Self-Review

**Spec coverage:**
- Async HTTPS server in same process → Task 2 (FastAPI) + Task 3 (Uvicorn, one process). ✅
- In-process TLS, same certs → Task 3 (`ssl_certfile`/`ssl_keyfile` → `/var/lib/tls`). ✅
- Different port (5000 gRPC / 5001 HTTP) → Global Constraints + Task 3. ✅
- Shared read-only `Config` only → Task 3 lifespan builds `Config`, stores on `app.state`; no mutable store. ✅
- Lifecycle via lifespan (startup start gRPC + SERVING; shutdown NOT_SERVING + `stop(grace=10)`) → Task 3. ✅
- Main thread owns Uvicorn/signals; gRPC in background → Task 3 (`uvicorn.run` on main thread; `server.start()` non-blocking). ✅
- Module split (config, grpc_service, http_app, __main__) + shared logging → Tasks 1–3. ✅
- `GET /healthz` → Task 2. ✅
- Deps fastapi + uvicorn[standard] via poetry → Task 2. ✅
- Dockerfile EXPOSE + CMD, k8s port + probe → Tasks 3–4. ✅
- Deferred single-use nonce store — intentionally not in this plan. ✅
- Post-merge assumptions (pydantic present, `tests/unit/` and `identity.py` exist, `app.py` differs) handled by the Pre-implementation reconciliation section. ✅

**Placeholder scan:** No TBD/TODO; every code step shows complete content; commands have expected output. ✅

**Type consistency:** `Config`, `build_store`, `verify_client_cert`, `register_services`, `create_app(lifespan=...)`, `build_grpc_server`, `lifespan` names/signatures are consistent across Tasks 1–4. ✅
