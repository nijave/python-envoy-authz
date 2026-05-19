# Integration Tests for python-envoy-authz

**Date:** 2026-05-18
**Status:** Approved

## Goal

Add a pytest-based integration test suite that exercises the gRPC Envoy
external authorization service end-to-end, covering the allow path, the
header-injection path, and the various denial paths.

## Scope

- **In scope:** Integration tests at the gRPC layer (real `grpc.server`,
  real TLS channel, real cert verification via `pyOpenSSL`).
- **Out of scope:** Unit tests of helper functions; refactoring `app.py`
  for dependency injection; load/perf testing.

## Constraints

`envoy_authz/app.py` reads `FRIGATE_X_PROXY_SECRET` and
`HA_CA_CERTIFICATE` at module import time and builds a process-global
`HA_CA_STORE` once. The test harness must set these env vars **before**
the module is imported anywhere. The user explicitly chose not to
refactor the app to take these as injected dependencies.

## Architecture

### Test layout

```
tests/
  __init__.py
  conftest.py              # fixtures + env-var prep + cert builders
  integration/
    __init__.py
    test_check.py          # gRPC Check() scenarios
```

### Fixtures (session-scoped unless noted)

1. **PKI setup (runs at conftest module import, before app import)**
   Generates ephemeral keys/certs with the `cryptography` library:
   - `trusted_ca` — set as `HA_CA_CERTIFICATE` env var
   - `untrusted_ca` — a separate CA, not trusted
   - `server_cert` + key — self-signed cert for the gRPC channel TLS
   - `trusted_client_cert` — signed by `trusted_ca`
   - `untrusted_client_cert` — signed by `untrusted_ca`
   - `self_signed_client_cert` — its own self-signed leaf

   Env vars set at conftest load:
   - `HA_CA_CERTIFICATE` = trusted CA PEM
   - `FRIGATE_X_PROXY_SECRET` = a deterministic test value

   After env vars are set, `envoy_authz.app` is imported.

2. **`grpc_server`** — Starts `grpc.server(ThreadPoolExecutor(...))`
   with `ssl_server_credentials([(server_key, server_cert)])`, binds to
   port `0` (OS allocates), registers `AuthorizationService`, yields
   `(server, port)`, and calls `server.stop(grace=None)` on teardown.

3. **`stub` (function-scoped)** — Returns
   `external_auth_pb2_grpc.AuthorizationStub` over a
   `grpc.secure_channel` with the server cert as trusted root and an SSL
   target name override matching the server cert's CN.

4. **`make_check_request` helper** — Plain function (not a fixture) that
   builds a `CheckRequest` with the requested host, path, and optional
   client certificate. URL-encodes the PEM before assigning it to
   `attributes.source.certificate`, matching what Envoy does in
   production.

### Why `cryptography` instead of `pyOpenSSL` for cert authoring

`pyOpenSSL` is already a project dependency (the production code uses
it for verification). However, building CA hierarchies with it is
verbose and partly deprecated. `cryptography` is a transitive
dependency of `pyOpenSSL` itself, so we add no new transitive footprint
in production by using it in tests. We add it as an explicit dev
dependency for clarity.

## Test matrix

| Test | Host | Path | Client cert | Expected |
|---|---|---|---|---|
| `test_frigate_metrics_no_cert_allowed` | `frigate.apps.somemissing.info` | `/api/metrics` | none | `OK` + `X-Proxy-Secret` header (Frigate's metrics endpoint requires the header to be present even on the no-auth path) |
| `test_frigate_with_valid_cert_injects_secret` | `frigate.apps.somemissing.info` | `/api/other` | trusted | `OK` + `X-Proxy-Secret` header with the configured value |
| `test_other_host_with_valid_cert_no_header` | `other.example.com` | `/any` | trusted | `OK`, no `X-Proxy-Secret` |
| `test_no_cert_on_non_metrics_denied` | `frigate.apps.somemissing.info` | `/api/events` | none | `PERMISSION_DENIED`, HTTP 403, body `{"error": "Unauthorized"}` |
| `test_wrong_path_on_frigate_without_cert_denied` | `frigate.apps.somemissing.info` | `/api/metrics_extra` | none | denied |
| `test_wrong_host_on_metrics_path_denied` | `not-frigate.example.com` | `/api/metrics` | none | denied |
| `test_cert_signed_by_different_ca_denied` | `other.example.com` | `/` | signed by `untrusted_ca` | denied |
| `test_malformed_cert_denied` | `other.example.com` | `/` | literal `"not-a-cert"` | denied, no server crash |
| `test_self_signed_client_cert_denied` | `other.example.com` | `/` | self-signed leaf | denied |

For each allow case, assertions check:
- `response.status.code == code_pb2.OK`
- The presence/absence of `X-Proxy-Secret` in `ok_response.headers`
- For Frigate: the header value equals the configured secret

For each deny case, assertions check:
- `response.status.code == code_pb2.PERMISSION_DENIED`
- `denied_response.status.code == http_status_pb2.StatusCode.Forbidden`
- `denied_response.body == '{"error": "Unauthorized"}'`

## Tooling changes

### `pyproject.toml`

Add to the `dev` dependency group:
- `pytest`
- `cryptography`

Add a `[tool.pytest.ini_options]` table:
- `testpaths = ["tests"]`
- `addopts = "-ra -q"`

### `.woodpecker.yaml`

Add a `test` step alongside the existing `lint` step, using the same
image and poetry version conventions:
```yaml
  test:
    # renovate: datasource=docker depName=python
    image: python:3.14-slim
    commands:
      - pip install poetry==2.2.1
      - poetry install --no-root --with dev
      - poetry run pytest
```

## Best practices applied

- Real cert verification path runs (no mocks of `verify_client_cert`)
- Real gRPC server with TLS (catches wiring and protobuf-shape bugs)
- One concern per test, names follow `test_<scenario>_<expected>`
- Arrange/Act/Assert structure
- OS-allocated port (no flakes from port collisions)
- Deterministic test secret value, asserted directly
- Clean teardown of the server in fixture finalizers

## Non-goals / explicitly excluded

- Unit tests of `verify_client_cert` in isolation
- Coverage reporting (user opted out)
- Refactoring `app.py` to take env config as constructor args
- Async test client (sync gRPC is sufficient for this service)
