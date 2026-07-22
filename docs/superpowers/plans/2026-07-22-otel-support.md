# OpenTelemetry tracing support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in OpenTelemetry **tracing** to the gRPC `ext_authz` server and the in-process FastAPI HTTPS server, exporting over OTLP, with the `Check` decision span enriched by the full parsed client identity.

**Architecture:** A new `envoy_authz/telemetry.py` owns all OTel wiring behind an opt-in gate (enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set and `OTEL_SDK_DISABLED != "true"`). `__main__.main()` configures the global `TracerProvider`, conditionally installs the gRPC + FastAPI instrumentors, and flushes the provider on shutdown. `AuthorizationService.Check` reads the auto-created server span and sets `authz.*` attributes best-effort.

**Tech Stack:** Python 3.12, grpcio (sync server), FastAPI/Uvicorn, `opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-grpc`, `opentelemetry-instrumentation-grpc`, `opentelemetry-instrumentation-fastapi`. Poetry for deps, pytest for tests, ruff for lint/format.

## Global Constraints

- Python `>=3.12`.
- **Traces only** — no metrics, no log export in this branch.
- **Opt-in:** telemetry is a hard no-op unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set (and not `OTEL_SDK_DISABLED=true`). The pytest suite and local `python -m envoy_authz` runs MUST emit nothing and attempt no network by default.
- **No hardcoded endpoint in Python** — the OTLP exporter reads endpoint/headers from standard `OTEL_EXPORTER_OTLP_*` env vars.
- Default `service.name` is `python-envoy-authz` (overridable via `OTEL_SERVICE_NAME`).
- Telemetry setup / attribute enrichment failures MUST never affect an authorization decision or crash the process.
- `k8s.yaml` is an **example** manifest, not the live deployment — any OTEL values added there are illustrative placeholders.
- Stage explicit paths in every commit (no blanket `git add`). Dependency style follows existing `pyproject.toml`: PEP 508 `(>=X,<Y)` entries written by `poetry add`.

## File Structure

| File | Responsibility |
| --- | --- |
| `envoy_authz/telemetry.py` | **New.** Opt-in gate (`_telemetry_enabled`), provider builder (`build_tracer_provider`), `setup_telemetry`, and instrumentor helpers (`instrument_grpc_server`, `instrument_fastapi`). |
| `envoy_authz/__main__.py` | **Modify.** Wire telemetry into `main()`; flush provider on lifespan shutdown. |
| `envoy_authz/grpc_service.py` | **Modify.** Enrich the `Check` server span with `authz.*` attributes incl. full identity. |
| `pyproject.toml` / `poetry.lock` | **Modify.** Add the four OTel dependencies. |
| `k8s.yaml` | **Modify.** Example-manifest comment + example OTEL env. |
| `tests/unit/test_telemetry.py` | **New.** Cover the opt-in gate and `setup_telemetry`. |
| `tests/unit/test_grpc_span.py` | **New.** Cover `Check` span enrichment (authorized + denied). |
| `tests/unit/test_main.py` | **Modify.** Cover conditional instrumentation + provider shutdown flush. |

---

### Task 1: Add OpenTelemetry dependencies

**Files:**
- Modify: `pyproject.toml` (`[project.dependencies]`)
- Modify: `poetry.lock`

**Interfaces:**
- Consumes: nothing.
- Produces: the packages `opentelemetry.sdk.trace`, `opentelemetry.exporter.otlp.proto.grpc.trace_exporter`, `opentelemetry.instrumentation.grpc`, `opentelemetry.instrumentation.fastapi` importable in the project venv.

- [ ] **Step 1: Add the dependencies via poetry**

```bash
poetry add \
  opentelemetry-sdk \
  opentelemetry-exporter-otlp-proto-grpc \
  opentelemetry-instrumentation-grpc \
  opentelemetry-instrumentation-fastapi
```

This appends four entries to `[project.dependencies]` in `pyproject.toml` and updates `poetry.lock`. If the resolver reports a `protobuf`/`grpcio` conflict with the existing buf.build-sourced packages, resolve by letting poetry pick compatible versions (do not downgrade `grpcio` below the existing `>=1.76.0` floor); if unavoidable, stop and report rather than loosening the gRPC pin.

- [ ] **Step 2: Verify the packages import**

Run:
```bash
poetry run python -c "import opentelemetry.sdk.trace, opentelemetry.exporter.otlp.proto.grpc.trace_exporter, opentelemetry.instrumentation.grpc, opentelemetry.instrumentation.fastapi; print('ok')"
```
Expected: prints `ok`, exit 0.

- [ ] **Step 3: Verify the existing suite still passes**

Run: `poetry run pytest -q`
Expected: PASS (same as before — no behavior change yet).

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml poetry.lock
git commit -m "build: add OpenTelemetry SDK, OTLP exporter, and gRPC/FastAPI instrumentation deps"
```

---

### Task 2: Telemetry module (opt-in gate + provider + instrumentors)

**Files:**
- Create: `envoy_authz/telemetry.py`
- Test: `tests/unit/test_telemetry.py`

**Interfaces:**
- Consumes: OTel SDK packages from Task 1; `importlib.metadata.version("envoy-authz")`.
- Produces (imported by Task 3):
  - `setup_telemetry() -> TracerProvider | None` — returns a configured provider when enabled (and sets it as the global provider), else `None`.
  - `build_tracer_provider() -> TracerProvider` — builds a provider without touching global state.
  - `instrument_grpc_server() -> None` — installs `GrpcInstrumentorServer` (global patch of `grpc.server`).
  - `instrument_fastapi(app) -> None` — instruments a FastAPI app instance.
  - `_telemetry_enabled() -> bool` — the opt-in gate.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_telemetry.py`:

```python
from unittest.mock import MagicMock

from opentelemetry.sdk.resources import SERVICE_NAME
from opentelemetry.sdk.trace import TracerProvider

from envoy_authz import telemetry


def test_disabled_when_no_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert telemetry._telemetry_enabled() is False


def test_disabled_when_sdk_disabled(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert telemetry._telemetry_enabled() is False


def test_enabled_when_endpoint_set(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert telemetry._telemetry_enabled() is True


def test_setup_returns_none_when_disabled(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    called = []
    monkeypatch.setattr(
        telemetry.trace, "set_tracer_provider", lambda p: called.append(p)
    )
    assert telemetry.setup_telemetry() is None
    assert called == []  # global provider left untouched


def test_setup_builds_and_installs_provider_when_enabled(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    installed = []
    monkeypatch.setattr(
        telemetry.trace, "set_tracer_provider", lambda p: installed.append(p)
    )
    provider = telemetry.setup_telemetry()
    assert isinstance(provider, TracerProvider)
    assert installed == [provider]


def test_build_provider_sets_default_service_name(monkeypatch):
    monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)
    provider = telemetry.build_tracer_provider()
    assert provider.resource.attributes[SERVICE_NAME] == "python-envoy-authz"


def test_setup_failure_is_non_fatal(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)

    def boom():
        raise RuntimeError("no exporter")

    monkeypatch.setattr(telemetry, "build_tracer_provider", boom)
    assert telemetry.setup_telemetry() is None  # swallowed, returns None


def test_instrument_fastapi_marks_app():
    from fastapi import FastAPI

    app = FastAPI()
    telemetry.instrument_fastapi(app)
    assert getattr(app, "_is_instrumented_by_opentelemetry", False) is True


def test_instrument_grpc_server_invokes_instrumentor(monkeypatch):
    instance = MagicMock()
    monkeypatch.setattr(
        telemetry, "GrpcInstrumentorServer", lambda: instance
    )
    telemetry.instrument_grpc_server()
    instance.instrument.assert_called_once_with()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `poetry run pytest tests/unit/test_telemetry.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'envoy_authz.telemetry'`.

- [ ] **Step 3: Write the implementation**

Create `envoy_authz/telemetry.py`:

```python
"""OpenTelemetry tracing setup for envoy_authz.

Opt-in: unless ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set (and ``OTEL_SDK_DISABLED``
is not ``"true"``), :func:`setup_telemetry` is a no-op and the global tracer
stays the default no-op provider. Enabling is purely env-driven; no endpoint is
hardcoded here. The OTLP exporter reads its endpoint/headers/timeout from the
standard ``OTEL_EXPORTER_OTLP_*`` environment variables.
"""

import logging
import os
from importlib.metadata import PackageNotFoundError, version

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.grpc import GrpcInstrumentorServer
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

logger = logging.getLogger(__name__)

DEFAULT_SERVICE_NAME = "python-envoy-authz"


def _service_version() -> str:
    try:
        return version("envoy-authz")
    except PackageNotFoundError:
        return "0.0.0"


def _telemetry_enabled() -> bool:
    """True iff OTLP export is configured and the SDK is not disabled."""
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
        return False
    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))


def build_tracer_provider() -> TracerProvider:
    """Build a TracerProvider with an OTLP/gRPC batch exporter.

    Does not touch global state; caller installs it via ``setup_telemetry``.
    """
    resource = Resource.create(
        {
            SERVICE_NAME: os.environ.get("OTEL_SERVICE_NAME", DEFAULT_SERVICE_NAME),
            SERVICE_VERSION: _service_version(),
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    return provider


def setup_telemetry() -> TracerProvider | None:
    """Install a global OTLP TracerProvider when telemetry is enabled.

    Returns the provider (also set as the global provider) when enabled, else
    ``None``. Any failure is logged and treated as disabled — never fatal.
    """
    if not _telemetry_enabled():
        logger.debug("OpenTelemetry disabled (no OTEL_EXPORTER_OTLP_ENDPOINT)")
        return None
    try:
        provider = build_tracer_provider()
        trace.set_tracer_provider(provider)
        logger.info("OpenTelemetry tracing enabled")
        return provider
    except Exception:
        logger.exception("Failed to set up OpenTelemetry; continuing without tracing")
        return None


def instrument_grpc_server() -> None:
    """Patch ``grpc.server`` to auto-create a span per RPC.

    Must run before the gRPC server is constructed.
    """
    GrpcInstrumentorServer().instrument()


def instrument_fastapi(app) -> None:
    """Instrument a FastAPI app instance to auto-create a span per request."""
    FastAPIInstrumentor.instrument_app(app)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `poetry run pytest tests/unit/test_telemetry.py -q`
Expected: PASS (all 9 tests).

- [ ] **Step 5: Lint/format**

Run: `poetry run ruff check envoy_authz/telemetry.py tests/unit/test_telemetry.py && poetry run ruff format envoy_authz/telemetry.py tests/unit/test_telemetry.py`
Expected: clean / reformatted.

- [ ] **Step 6: Commit**

```bash
git add envoy_authz/telemetry.py tests/unit/test_telemetry.py
git commit -m "feat: add opt-in OpenTelemetry tracing setup module"
```

---

### Task 3: Wire telemetry into the entrypoint

**Files:**
- Modify: `envoy_authz/__main__.py`
- Test: `tests/unit/test_main.py`

**Interfaces:**
- Consumes: `setup_telemetry`, `instrument_grpc_server`, `instrument_fastapi` from Task 2.
- Produces: `main()` that (a) calls `setup_telemetry()`, (b) when a provider is returned installs both instrumentors — gRPC **before** the app is built — and (c) stashes the provider on `app.state.tracer_provider`; `lifespan` flushes that provider on shutdown.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_main.py`:

```python
def test_main_sets_up_and_instruments_when_enabled(monkeypatch):
    fake_provider = MagicMock()
    calls = []
    fake_app = MagicMock()

    monkeypatch.setattr(main_module, "setup_telemetry", lambda: fake_provider)
    monkeypatch.setattr(
        main_module, "instrument_grpc_server", lambda: calls.append("grpc")
    )
    monkeypatch.setattr(
        main_module, "instrument_fastapi", lambda app: calls.append("fastapi")
    )
    monkeypatch.setattr(main_module, "create_app", lambda lifespan: fake_app)
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)

    main_module.main()

    # gRPC instrumentor runs before FastAPI (must patch grpc.server pre-build).
    assert calls == ["grpc", "fastapi"]
    assert fake_app.state.tracer_provider is fake_provider


def test_main_skips_instrumentation_when_disabled(monkeypatch):
    calls = []
    fake_app = MagicMock()

    monkeypatch.setattr(main_module, "setup_telemetry", lambda: None)
    monkeypatch.setattr(
        main_module, "instrument_grpc_server", lambda: calls.append("grpc")
    )
    monkeypatch.setattr(
        main_module, "instrument_fastapi", lambda app: calls.append("fastapi")
    )
    monkeypatch.setattr(main_module, "create_app", lambda lifespan: fake_app)
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **k: None)

    main_module.main()

    assert calls == []
    assert fake_app.state.tracer_provider is None


def test_lifespan_flushes_tracer_provider(monkeypatch):
    fake_config = object()
    fake_server = MagicMock()
    fake_health = MagicMock()
    fake_provider = MagicMock()

    monkeypatch.setattr(main_module, "load_config", lambda: fake_config)
    monkeypatch.setattr(
        main_module, "build_grpc_server", lambda config: (fake_server, fake_health)
    )

    app = MagicMock()
    app.state.tracer_provider = fake_provider

    async def run():
        async with main_module.lifespan(app):
            pass

    asyncio.run(run())

    fake_provider.shutdown.assert_called_once_with()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `poetry run pytest tests/unit/test_main.py -q`
Expected: FAIL — new tests error (`AttributeError: <module> does not have the attribute 'setup_telemetry'`) and `test_lifespan_flushes_tracer_provider` fails (`shutdown` not called).

- [ ] **Step 3: Update `__main__.py`**

Add the import near the existing local imports (after line 14, `from .http_app import create_app`):

```python
from .telemetry import (
    instrument_fastapi,
    instrument_grpc_server,
    setup_telemetry,
)
```

Replace the `lifespan` `finally` block so it flushes the provider after draining gRPC. The full updated `lifespan` reads:

```python
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    server, health_servicer = build_grpc_server(config)
    try:
        server.start()
        health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        logger.info("Secure gRPC server started on port %s", GRPC_PORT)
        app.state.config = config
        yield
    finally:
        logger.info("Draining gRPC server...")
        health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        stopped = server.stop(grace=10)
        await asyncio.to_thread(stopped.wait)
        provider = getattr(app.state, "tracer_provider", None)
        if provider is not None:
            provider.shutdown()
```

Replace `main()` with:

```python
def main():
    provider = setup_telemetry()
    if provider is not None:
        # Must patch grpc.server before build_grpc_server runs in the lifespan.
        instrument_grpc_server()
    app = create_app(lifespan=lifespan)
    if provider is not None:
        instrument_fastapi(app)
    app.state.tracer_provider = provider
    logger.info("Starting HTTPS server on port %s", HTTP_PORT)
    uvicorn.run(
        app,
        host="::",
        port=HTTP_PORT,
        ssl_certfile=TLS_CERT_PATH,
        ssl_keyfile=TLS_KEY_PATH,
        log_config=None,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `poetry run pytest tests/unit/test_main.py -q`
Expected: PASS (the original `test_lifespan_starts_and_drains_grpc_server` plus the 3 new tests).

- [ ] **Step 5: Lint/format**

Run: `poetry run ruff check envoy_authz/__main__.py tests/unit/test_main.py && poetry run ruff format envoy_authz/__main__.py tests/unit/test_main.py`
Expected: clean / reformatted.

- [ ] **Step 6: Commit**

```bash
git add envoy_authz/__main__.py tests/unit/test_main.py
git commit -m "feat: configure OpenTelemetry tracing in the entrypoint"
```

---

### Task 4: Enrich the Check server span

**Files:**
- Modify: `envoy_authz/grpc_service.py`
- Test: `tests/unit/test_grpc_span.py`

**Interfaces:**
- Consumes: `opentelemetry.trace.get_current_span()`; the existing `parse_client_identity` and `verify_client_cert`.
- Produces: on each `Check` call, sets on the current span: `authz.allowed` (bool), `authz.host` (str), `authz.path` (str), `authz.frigate_metrics_bypass` (bool), and — when a client cert verified — `authz.identity.<field>` for every non-empty field of the parsed identity. No new public functions.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_grpc_span.py`:

```python
from unittest.mock import MagicMock

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from envoy_authz.grpc_service import AuthorizationService


def _run_check_in_span(servicer, request):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("Check"):
        servicer.Check(request, MagicMock())
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    return spans[0].attributes


def test_check_span_authorized_carries_identity(
    ha_config, check_request, trusted_client_cert_pem
):
    servicer = AuthorizationService(ha_config)
    request = check_request(
        host="example.somemissing.info",
        path="/",
        client_cert_pem=trusted_client_cert_pem,
    )
    attrs = _run_check_in_span(servicer, request)
    assert attrs["authz.allowed"] is True
    assert attrs["authz.host"] == "example.somemissing.info"
    assert attrs["authz.path"] == "/"
    assert attrs["authz.frigate_metrics_bypass"] is False
    assert (
        attrs["authz.identity.common_name"]
        == "trusted-client.ha.apps.somemissing.info"
    )
    assert "clientAuth" in attrs["authz.identity.extended_key_usages"]


def test_check_span_denied_has_no_identity(ha_config, check_request):
    servicer = AuthorizationService(ha_config)
    request = check_request(host="example.somemissing.info", path="/")
    attrs = _run_check_in_span(servicer, request)
    assert attrs["authz.allowed"] is False
    assert "authz.identity.common_name" not in attrs
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `poetry run pytest tests/unit/test_grpc_span.py -q`
Expected: FAIL — `KeyError: 'authz.allowed'` (attributes not set yet).

- [ ] **Step 3: Update `grpc_service.py`**

Add the import after the existing imports (below line 10, `from google.rpc import code_pb2, status_pb2`):

```python
from opentelemetry import trace
```

Add this module-level helper below the `FRIGATE_HOST` constant (after line 18):

```python
def _record_span(
    *, allowed: bool, host: str, path: str, frigate_bypass: bool, client_cert
) -> None:
    """Annotate the current span with the authz decision (best-effort).

    A tracing failure must never affect the decision, so everything here is
    wrapped and swallowed. When telemetry is disabled the current span is a
    no-op and every set_attribute call is a cheap no-op.
    """
    span = trace.get_current_span()
    try:
        span.set_attribute("authz.allowed", allowed)
        span.set_attribute("authz.host", host)
        span.set_attribute("authz.path", path)
        span.set_attribute("authz.frigate_metrics_bypass", frigate_bypass)
        if client_cert is not None:
            identity = parse_client_identity(client_cert).model_dump(
                exclude_none=True
            )
            for key, value in identity.items():
                # Skip empty lists; OTel rejects ambiguous empty sequences.
                if isinstance(value, list) and not value:
                    continue
                span.set_attribute(f"authz.identity.{key}", value)
    except Exception:
        logger.exception("Failed to record authz span attributes")
```

In `Check`, compute the frigate-metrics bypass explicitly and record the span. Replace the `allowed = (...)` assignment block (lines 52-61) with:

```python
        # Figure out if a request should be allowed (can be arbitrary criteria)
        frigate_metrics_bypass = (
            # Requests to the frigate metrics endpoint don't need auth
            request.attributes.request.http.host == FRIGATE_HOST
            and path == "/api/metrics"
        )
        allowed = frigate_metrics_bypass or (
            # Requests should contain a valid client certificate from the
            # Home Assistant CA
            client_cert is not None
        )

        _record_span(
            allowed=allowed,
            host=request.attributes.request.http.host,
            path=path,
            frigate_bypass=frigate_metrics_bypass,
            client_cert=client_cert,
        )
```

(The rest of `Check` — the `if allowed:` branch and below — is unchanged.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `poetry run pytest tests/unit/test_grpc_span.py -q`
Expected: PASS (both tests).

- [ ] **Step 5: Run the full suite (guard against regressions)**

Run: `poetry run pytest -q`
Expected: PASS — existing gRPC/HTTP/identity tests unaffected (telemetry disabled by default; no span provider installed → `get_current_span` returns the no-op span).

- [ ] **Step 6: Lint/format**

Run: `poetry run ruff check envoy_authz/grpc_service.py tests/unit/test_grpc_span.py && poetry run ruff format envoy_authz/grpc_service.py tests/unit/test_grpc_span.py`
Expected: clean / reformatted.

- [ ] **Step 7: Commit**

```bash
git add envoy_authz/grpc_service.py tests/unit/test_grpc_span.py
git commit -m "feat: enrich Check span with authz decision and client identity"
```

---

### Task 5: Example OTEL config in k8s manifest

**Files:**
- Modify: `k8s.yaml`

**Interfaces:**
- Consumes: nothing (documentation/example only).
- Produces: no code interface; an example env block + a clarifying comment.

- [ ] **Step 1: Add the example-manifest comment**

Prepend a comment at the very top of `k8s.yaml` (above the first `---`):

```yaml
# NOTE: This is an EXAMPLE manifest, not the live deployment. The real
# deployment is maintained out-of-tree; this file exists to illustrate how to
# run python-envoy-authz on Kubernetes. Adapt names, namespaces, secrets, and
# the OTEL_* values below to your environment before applying.
```

- [ ] **Step 2: Add example OTEL env to the deployment container**

In the `python-envoy-authz` Deployment, extend the container `env:` list (currently ending after the `HA_CA_CERTIFICATE` block, around `k8s.yaml:62-66`) with two example entries:

```yaml
          # Example OpenTelemetry config. Tracing is opt-in: it stays disabled
          # until OTEL_EXPORTER_OTLP_ENDPOINT is set. Point this at your own
          # OTLP/gRPC collector (this value is an example placeholder).
          - name: OTEL_EXPORTER_OTLP_ENDPOINT
            value: "http://otel-collector.observability:4317"
          - name: OTEL_SERVICE_NAME
            value: "python-envoy-authz"
```

- [ ] **Step 3: Verify the YAML still parses**

Run:
```bash
poetry run python -c "import yaml,sys; list(yaml.safe_load_all(open('k8s.yaml'))); print('ok')"
```
Expected: prints `ok`, exit 0. (If PyYAML is not available, use `kubectl apply --dry-run=client -f k8s.yaml` instead, or any local YAML linter.)

- [ ] **Step 4: Commit**

```bash
git add k8s.yaml
git commit -m "docs: mark k8s.yaml as example and add example OTEL config"
```

---

## Final verification

- [ ] Run the full suite: `poetry run pytest -q` → PASS.
- [ ] Run lint: `poetry run ruff check .` → clean.
- [ ] Confirm default-off: `poetry run python -c "from envoy_authz.telemetry import _telemetry_enabled; assert _telemetry_enabled() is False; print('disabled by default: ok')"` (with `OTEL_EXPORTER_OTLP_ENDPOINT` unset) → prints ok.

## Self-Review notes

- **Spec coverage:** new `telemetry.py` module + opt-in gate (Task 2); OTLP/gRPC exporter + BatchSpanProcessor + resource defaults (Task 2); `main()` wiring with gRPC-before-build ordering + shutdown flush (Task 3); Check span enrichment incl. full identity (Task 4); example k8s config + example-manifest comment (Task 5); dependencies (Task 1); tests for gate, setup, wiring, and enrichment (Tasks 2–4). Metrics/logs explicitly deferred — no task, matching spec scope.
- **Signature note vs spec:** spec sketched `setup_telemetry() -> bool`; refined to return `TracerProvider | None` so `main()` can flush on shutdown. Truthiness preserves the "enabled" gate semantics.
