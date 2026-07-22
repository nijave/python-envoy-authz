# In-process HTTPS server alongside gRPC — design

**Date:** 2026-07-21
**Status:** Approved (brainstorming)
**Related:** sibling project `python-client-idp` (Flask/authlib OIDC broker); this
service's existing `ext_authz` gRPC server (`envoy_authz/app.py`).

## Problem

`python-envoy-authz` currently runs a single synchronous gRPC server
(`grpc.server(ThreadPoolExecutor)`) that implements Envoy's external
authorization (`ext_authz`) `Check` RPC, terminating TLS in-process on port
`5000` with certs from `/var/lib/tls/`.

We want to add an **HTTPS server for HTTP/1.1 requests** to the same service, to
host a custom app API / webhook surface (related to the `python-client-idp`
work). Requirements from the requester:

- Same or different port — **different port** chosen (see Decisions).
- **Same certs** — TLS terminated in-process using the same
  `/var/lib/tls/tls.crt` + `tls.key`.
- **Shared process memory** so data can be shared between the gRPC and HTTP
  sides without an external datastore.
- The HTTP server should be **async or threaded** (not a single-threaded
  blocking dev server).

## Scope (this step)

This step delivers the **server plumbing only**:

- Run an async HTTPS server (FastAPI + Uvicorn) in the **same process** as the
  existing sync gRPC server.
- In-process TLS with the same certs, on a different port.
- Share the existing **read-only `Config`** (including `ha_ca_store`) with both
  the gRPC servicer and the HTTP app.
- One representative route — **`GET /healthz`** — to prove the server is wired
  and TLS works.
- A targeted refactor of the single `app.py` module into a small package so both
  entrypoints can import shared pieces cleanly.

### Explicitly out of scope (deferred to a future spec)

- **Shared *mutable* state / single-use nonce store.** Investigation confirmed
  (a) this project has no mutable state today — `ha_ca_store` is read-only after
  startup (`app.py:33-34`), and (b) the sibling `python-client-idp` deliberately
  removed its `USED_NONCES` set and in-memory `CODES` map in favor of stateless
  signed authorization codes (commits `de4d62b`, `454f088`;
  `python-client-idp/docs/.../2026-07-18-...-design.md:259-263`).
  A single-use (replay-protected) nonce is inherently stateful and, when built,
  will need a thread-safe/async-safe shared store. It is **not needed at this
  step** and will get its own spec so it is designed with the real flow in hand.
  See "Future work" for the intended shape so today's boundaries are
  intentional.

## Decisions

- **Different port for HTTP.** gRPC speaks HTTP/2 and the HTTP app speaks
  HTTP/1.1; sharing one port would require ALPN protocol-muxing that neither
  server supports jointly. gRPC stays on `5000`; HTTP listens on `5001`
  (configurable via `HTTP_PORT`, default `5001`).
- **FastAPI + Uvicorn (async), single process.** Framework was left open by the
  requester with a preference for async/threaded. FastAPI is idiomatic for a
  JSON API + webhook receiver, reuses **pydantic** (already a dependency), and
  Uvicorn terminates TLS in-process via `ssl_certfile`/`ssl_keyfile`.
  `uvicorn[standard]` is used for the C-speed extras (uvloop event loop +
  httptools parser).
- **Single process, no multi-worker servers.** Shared process memory rules out
  fork/worker models (gunicorn, `uvicorn --workers N`). Objects passed to both
  sides live in one address space and are shared directly.
- **Main thread owns Uvicorn (and signals); gRPC runs in the background.**
  `grpc.Server.start()` is non-blocking, so its worker threads run in the
  background while Uvicorn blocks the main thread and handles SIGTERM/SIGINT.
  This avoids the "asyncio event loop in a non-main thread cannot install signal
  handlers" pitfall.
- **Lifecycle via FastAPI `lifespan`.** The gRPC server is started on app
  startup and drained on app shutdown, replacing today's manual
  `signal.signal(...)` handlers.

## Architecture

```
                      one Python process
  ┌───────────────────────────────────────────────────────────┐
  │  main thread: Uvicorn (asyncio) ── FastAPI app  :5001 (TLS) │
  │        │ owns SIGTERM/SIGINT                                │
  │        │ lifespan startup/shutdown                          │
  │        ▼                                                    │
  │  gRPC server (ThreadPoolExecutor worker threads) :5000(TLS) │
  │        AuthorizationService.Check                           │
  │                                                             │
  │  shared: Config (read-only: ha_ca_store, secrets)           │
  └───────────────────────────────────────────────────────────┘
        both listeners load /var/lib/tls/tls.{crt,key}
```

### Lifecycle

- **Startup (lifespan enter):** `load_config()` → build gRPC server, register
  `AuthorizationService(config)` + health servicer, `add_secure_port("[::]:5000",
  creds)`, `server.start()`, health `SERVING`. Stash the server + health servicer
  on `app.state` (or in a small holder) for shutdown.
- **Serve:** Uvicorn serves the FastAPI app on `:5001` with TLS.
- **Shutdown (lifespan exit, on SIGTERM/SIGINT):** health `NOT_SERVING` (so
  Envoy stops routing) → `grpc_server.stop(grace=10)` → Uvicorn finishes
  draining HTTP.

## Module layout

Turn the flat `envoy_authz/app.py` into a package (add `envoy_authz/__init__.py`)
and split by responsibility:

| Module | Responsibility |
| --- | --- |
| `envoy_authz/config.py` | `Config` dataclass, `load_config`, `build_store`, `configure_crl`, `verify_client_cert` (moved verbatim from `app.py`). |
| `envoy_authz/grpc_service.py` | `AuthorizationService` servicer (moved verbatim). `FRIGATE_HOST` constant. |
| `envoy_authz/http_app.py` | `create_app(config: Config) -> FastAPI` factory; `GET /healthz` route; logging setup shared or imported. |
| `envoy_authz/__main__.py` | Wires everything: builds `Config`, defines the `lifespan` that owns the gRPC server, constructs the FastAPI app via `create_app`, runs Uvicorn with TLS. |

Logging config (the JSON logger setup currently at `app.py:22-25`) moves to a
shared location imported by both entrypoints (e.g. top of `__init__.py` or a
`logging_setup` helper) so gRPC and HTTP emit consistent JSON logs.

`app.py` is removed once its contents are split (or kept as a thin shim that
imports from the package, if a transition is desired — default is to remove it).

### `GET /healthz`

Returns `200` with a small JSON body (e.g. `{"status": "ok"}`). This is a plain
liveness signal proving the HTTPS listener + TLS are up; it does **not** check
gRPC health (gRPC has its own `grpc_health_probe`). No auth.

## Dependencies

Add to `[project.dependencies]` in `pyproject.toml` via poetry:

- `fastapi (>=0.115,<1.0)`
- `uvicorn[standard] (>=0.30,<1.0)`

(pydantic is already present.) Regenerate `poetry.lock`.

## Deployment changes

- **Dockerfile:** `EXPOSE 5000 5001`; change `CMD` from
  `python3 envoy_authz/app.py` to `python -m envoy_authz`.
- **k8s.yaml:**
  - Add a second container port `http`/`5001` alongside `grpc`/`5000`.
  - Add an HTTP liveness/readiness probe hitting `https://localhost:5001/healthz`
    (httpGet with `scheme: HTTPS`), keeping the existing gRPC probes for `5000`.
  - Add a Service port mapping for the HTTP surface as needed by its consumer
    (left to the consuming spec; the plumbing spec only guarantees the port is
    listening).
- The same mounted `python-envoy-authz-tls-cert` secret at `/var/lib/tls`
  already provides `tls.crt`/`tls.key`; no new secret needed.

## Error handling

- **Missing/invalid cert files at startup:** Uvicorn fails fast if
  `ssl_certfile`/`ssl_keyfile` cannot be loaded — same failure surface as the
  existing gRPC `ssl_server_credentials` path. Acceptable (fail on boot).
- **gRPC start failure during lifespan startup:** propagate the exception so the
  process exits non-zero rather than serving HTTP with a dead authz path.
- **Shutdown ordering:** health flips to `NOT_SERVING` before `stop(grace=10)` so
  in-flight requests drain while Envoy stops routing.

## Testing

- **`GET /healthz`** via FastAPI `TestClient` — returns 200 and expected body.
- **`create_app(config)`** wires without error given a minimal/fake `Config`.
- **Module-split regression:** existing gRPC unit/integration tests continue to
  pass against the moved `AuthorizationService`/`verify_client_cert` (update
  imports only; behavior unchanged).
- TLS itself is exercised at the integration/deploy layer (probes), not unit
  tests.

## Future work (deferred)

When the single-use nonce flow is built, add a shared store designed for
**cross-paradigm** access (async FastAPI coroutines + sync gRPC worker threads
touching the same object):

- A dedicated `ThreadSafeStore` class wrapping a dict guarded by a
  `threading.Lock`, with short critical sections and **no `await` held under the
  lock** (safe from both sync threads and async coroutines for pure in-memory
  ops).
- Intention-revealing methods (`set(key, value, ttl=...)`, `get`, `pop`,
  delete-on-consume, TTL expiry on read) rather than a raw dict.
- A single instance passed to both `AuthorizationService` and the FastAPI app.
- Its own spec covering the actual nonce issue/verify flow and threat model.
