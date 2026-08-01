# python-envoy-authz

An Envoy **external authorization** (ext_authz) gRPC service for a home
infrastructure. It does two things:

1. **mTLS + Frigate proxy secret** — verifies the client certificate against a
   configured HA CA (+ CRL), requires the `clientAuth` EKU, and on the Frigate
   path injects a trusted `X-Proxy-Secret` header upstream.
2. **mTLS → OAuth2 federation** (opt-in) — for a request host claimed by a
   configured provider, derives a stable subject from the client cert,
   obtains/reuses an OAuth2 session with that downstream backend (Vikunja), and
   injects `Authorization: Bearer …` upstream. It also runs a small OAuth2/OIDC
   Provider (OP) so Vikunja can redeem the federation auth code. Any other
   allowed host passes through with no header added.

See **[docs/federation.md](docs/federation.md)** for the full topology, the
`get_bearer` decision ladder, the OP endpoints, the deny policy, and the
`providers.yaml` schema.

## Run

```bash
poetry install
# Required env: FRIGATE_X_PROXY_SECRET, HA_CA_CERTIFICATE
# Federation is OPT-IN: also set IDP_ISSUER, SECRET_KEY and PROVIDERS_FILE to
# enable it (with any of them unset the service runs the mTLS + Frigate gate
# only). See docs/federation.md for the full list, incl. OP_KEY_PATH.
# Also required: TLS cert+key at TLS_CERT_PATH/TLS_KEY_PATH (the gRPC + OP HTTPS
# servers will not start without them; defaults /var/lib/tls/tls.{crt,key}).
poetry run python -m envoy_authz
```

The service serves ext_authz gRPC on `GRPC_PORT` (default 5000, mTLS) and the
OP HTTPS endpoints on `HTTP_PORT` (default 5001).

## Test

```bash
poetry run pytest                       # unit + in-process federation tests
poetry run pytest tests/integration -v  # real-TLS gRPC suite (+ 1 skipped live test)
```

The live Vikunja integration test is skipped unless `RUN_INTEGRATION=1`; bring
up the stack with `docker compose -f docker-compose.vikunja.yml up -d --build`
(see docs/federation.md).

## Configuration

All configuration is environment-driven (`pydantic-settings`); secrets are
`SecretStr`. The full variable table and the downstream-provider schema live in
[docs/federation.md](docs/federation.md).
