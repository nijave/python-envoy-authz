# OpenTelemetry tracing support — design

**Date:** 2026-07-22
**Status:** Approved (brainstorming)
**Branch:** `feat/otel-support` (stacked on `feat/in-process-https-server`)
**Related:** this service's gRPC `ext_authz` server (`envoy_authz/grpc_service.py`)
and in-process FastAPI HTTPS server (`envoy_authz/__main__.py`,
`envoy_authz/http_app.py`).

## Problem

`python-envoy-authz` runs a synchronous gRPC `ext_authz` `Check` server plus an
in-process FastAPI/Uvicorn HTTPS server (`/healthz`). There is currently no
distributed tracing: when an authorization decision is slow or surprising there
is no per-request span, no latency breakdown, and no way to correlate a decision
with the client identity that produced it.

We want **OpenTelemetry tracing** wired into both the gRPC and HTTP surfaces,
exporting over OTLP to the homelab collector (HyperDX/ClickHouse), while keeping
local runs and the test suite completely silent unless explicitly enabled.

## Scope (this step)

- **Traces only.** Metrics and logs are out of scope for this branch.
- **In-process SDK setup** (no `opentelemetry-instrument` zero-code wrapper), so
  `python -m envoy_authz` stays the single entrypoint and span content is under
  our control.
- **Opt-in via standard `OTEL_*` env vars.** Telemetry is a no-op unless
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set (and not disabled via
  `OTEL_SDK_DISABLED=true`).
- **Auto-instrument** the sync gRPC server and the FastAPI app via the official
  instrumentation libraries.
- **Enrich the `Check` server span** with authorization attributes, including
  the full parsed client identity (low-volume home setup; searchability is worth
  more than cardinality concerns here).
- Add an **example** OTLP configuration to `k8s.yaml`, clearly marked as an
  example manifest (see Deployment).

### Explicitly out of scope

- **Metrics** (authorized/denied counters, Check-latency histograms) and **log
  export / trace-log correlation.** Both are natural follow-ups but are not part
  of this branch.
- Custom sampling policy beyond the SDK/env defaults (`OTEL_TRACES_SAMPLER`).

## Decisions

- **Opt-in gate on `OTEL_EXPORTER_OTLP_ENDPOINT`.** If the endpoint env var is
  absent, `setup_telemetry()` returns `False` and installs no exporter — the
  global tracer stays the default no-op provider, so `trace.get_current_span()`
  calls in the handler are cheap no-ops. `OTEL_SDK_DISABLED=true` also forces the
  no-op path even if an endpoint is set. This keeps `pytest` and local
  `python -m envoy_authz` runs from emitting or attempting to connect anywhere.
- **OTLP/gRPC exporter (`opentelemetry-exporter-otlp-proto-grpc`).** The homelab
  collector accepts OTLP gRPC on `4317`. The exporter reads its endpoint,
  headers, and timeout from the standard `OTEL_EXPORTER_OTLP_*` env vars, so no
  endpoint is hardcoded in Python.
- **`BatchSpanProcessor`.** Standard batching/backpressure; flushed on shutdown
  (see Lifecycle).
- **Resource from env + defaults.** `service.name` defaults to
  `python-envoy-authz` (overridable via `OTEL_SERVICE_NAME`), `service.version`
  from the installed package version; `Resource.create()` still merges anything
  in `OTEL_RESOURCE_ATTRIBUTES`.
- **Sync gRPC instrumentor.** The server is sync
  (`grpc.server(ThreadPoolExecutor)`), so `GrpcInstrumentorServer` (not the
  `aio` variant) is correct. It **globally patches `grpc.server`**, so it must be
  invoked *before* `build_grpc_server()` constructs the server.
- **Full identity on spans.** Deliberate: low traffic + sampling, and having the
  parsed identity searchable in the trace backend is the main debugging payoff.

## Architecture

```
                       one Python process
  ┌──────────────────────────────────────────────────────────────┐
  │ main(): setup_telemetry()  → global TracerProvider (or no-op)  │
  │         instrument_grpc_server()   (patches grpc.server)       │
  │         create_app(); instrument_fastapi(app)                  │
  │                                                                │
  │  FastAPI/Uvicorn :5001 ──[FastAPIInstrumentor]── server spans  │
  │  gRPC server     :5000 ──[GrpcInstrumentorServer]─ Check span  │
  │        AuthorizationService.Check enriches current span        │
  │                                                                │
  │  BatchSpanProcessor → OTLPSpanExporter → collector :4317       │
  │  (only when OTEL_EXPORTER_OTLP_ENDPOINT is set)                │
  └──────────────────────────────────────────────────────────────┘
```

## Module layout

New module plus small touches to two existing files:

| Module | Change |
| --- | --- |
| `envoy_authz/telemetry.py` | **New.** `setup_telemetry() -> bool`, `instrument_grpc_server()`, `instrument_fastapi(app)`. Holds all OTel wiring and the opt-in gate. |
| `envoy_authz/__main__.py` | Call `setup_telemetry()` + `instrument_grpc_server()` at the top of `main()` (before app/lifespan); call `instrument_fastapi(app)` right after `create_app`. Flush the tracer provider on lifespan shutdown. |
| `envoy_authz/grpc_service.py` | In `Check`, fetch `trace.get_current_span()` and set authorization attributes (incl. full identity). No new control flow; all no-ops when disabled. |

### `envoy_authz/telemetry.py`

```python
def setup_telemetry() -> bool:
    """Configure a global OTLP TracerProvider if OTEL is enabled.

    Enabled iff OTEL_EXPORTER_OTLP_ENDPOINT is set and OTEL_SDK_DISABLED is not
    'true'. Returns True when a real provider was installed, else False (no-op).
    """
```

- Builds `Resource.create({SERVICE_NAME: os.environ.get("OTEL_SERVICE_NAME", "python-envoy-authz"), SERVICE_VERSION: <pkg version>})`.
- `TracerProvider(resource=...)` + `BatchSpanProcessor(OTLPSpanExporter())`; `trace.set_tracer_provider(provider)`.
- `instrument_grpc_server()` → `GrpcInstrumentorServer().instrument()`.
- `instrument_fastapi(app)` → `FastAPIInstrumentor.instrument_app(app)`.

### `Check` span enrichment (`grpc_service.py`)

Set on `trace.get_current_span()`:

- `authz.allowed` (bool)
- `authz.host`, `authz.path`
- `authz.frigate_metrics_bypass` (bool — the host+path bypass case)
- When a client cert verified and parses: flatten the parsed identity
  (`parse_client_identity(cert).model_dump(exclude_none=True)`) into
  `authz.identity.<field>` string attributes. Best-effort and wrapped so a
  parse/attribute failure never affects the decision (mirrors the existing
  best-effort identity logging).

## Lifecycle / shutdown

On lifespan shutdown (after the gRPC drain), call the tracer provider's
`shutdown()` (which flushes the `BatchSpanProcessor`) so buffered spans are
exported before exit. Guarded so it's a no-op when telemetry was never enabled.

## Dependencies

Add to `[project.dependencies]` in `pyproject.toml` via poetry, then regenerate
`poetry.lock`:

- `opentelemetry-sdk`
- `opentelemetry-exporter-otlp-proto-grpc`
- `opentelemetry-instrumentation-grpc`
- `opentelemetry-instrumentation-fastapi`

(`opentelemetry-api` comes transitively.) Version constraints follow the
existing style (`>=X,<next-major`) using whatever poetry resolves as current.

## Deployment changes

**`k8s.yaml` is an example manifest, not the live deployment.** The real
deployment is maintained out-of-tree; this repo is open source and `k8s.yaml`
exists only to illustrate how to run the service. This branch will:

- Add a clear comment at the top of `k8s.yaml` stating it is an example to adapt,
  not the deployed configuration.
- Add **example** env to the deployment container:
  - `OTEL_EXPORTER_OTLP_ENDPOINT` — placeholder pointing at an in-cluster
    collector (e.g. `http://otel-collector.observability:4317`), clearly marked
    as an example value to change.
  - `OTEL_SERVICE_NAME: python-envoy-authz`.
- No Dockerfile change: the entrypoint stays `python -m envoy_authz`; enabling
  telemetry is purely env-driven.

## Error handling

- **Collector unreachable:** `BatchSpanProcessor` + OTLP exporter retry/drop in
  the background; export failures never surface into the request path or crash
  the process.
- **Telemetry setup failure** (bad env, import issue): should not take down the
  authz service. `setup_telemetry()` failures are logged and treated as disabled
  rather than fatal.
- **Attribute enrichment failure** in `Check`: caught and logged best-effort;
  the authorization decision is unaffected.

## Testing

- `setup_telemetry()` returns `False` and installs no real provider when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is unset (and when `OTEL_SDK_DISABLED=true`).
- `setup_telemetry()` returns `True` and sets a `TracerProvider` when the
  endpoint env var is set (monkeypatched; no real network — assert on the
  installed provider type, not on export).
- `Check` span enrichment: drive the servicer with a `TracerProvider` backed by
  an `InMemorySpanExporter` and assert the emitted span carries `authz.allowed`,
  `authz.host`, `authz.path`, and (authorized-with-cert case) the
  `authz.identity.*` attributes. Cover both an authorized and a denied request.
- Existing gRPC/HTTP unit + integration tests continue to pass unchanged
  (telemetry disabled by default under pytest).

## Future work (deferred)

- **Metrics:** authorized/denied counters and a `Check` latency histogram via the
  OTel metrics SDK + OTLP metric exporter.
- **Logs:** route `python-json-logger` output through the OTel logging exporter
  and correlate with `trace_id`/`span_id`.
