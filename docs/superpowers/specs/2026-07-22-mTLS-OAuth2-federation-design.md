# mTLS → OAuth2 federation design

Date: 2026-07-22

## Project intention

This service becomes an **mTLS-terminated federation proxy**. An end user
authenticates to Envoy with a client certificate; this service verifies the
cert, then **federates the user into a Vikunja OAuth2 session by logging in on
their behalf** and injecting the resulting Vikunja bearer token upstream. The
federation is triggered on the Envoy `ext_authz` gRPC `Check` path, with
session reuse so a fresh OIDC handshake only happens when the cached session is
absent or stale.

The OAuth2/OIDC Provider machinery is ported from
`/home/nick/Documents/workspace/misc/python-client-idp` (an authenticating
proxy / OIDC broker) and adapted to this codebase. That project's own design
spec (`docs/superpowers/specs/2026-07-18-email-header-vikunja-broker-design.md`)
explicitly deferred exactly this work: the `ext_authz` transport, the response
mode, per-request JWT caching, and replacing the placeholder `Authorization:
Email <addr>` trust boundary with a real upstream protocol. The mTLS client
certificate — already verified by this service today — is that real upstream
protocol.

### What "federation" means here

This service plays two roles at once, both ported and adapted from
python-client-idp:

- **OIDC Provider (OP)** to Vikunja: serves discovery, `/jwks.json`,
  `/oauth/token`, `/oauth/userinfo`. Vikunja is an OIDC relying party; it
  discovers this OP, exchanges an authorization code for an `id_token`, and
  issues its own Vikunja JWT.
- **Federator**: takes a verified mTLS identity, mints a stateless OP
  authorization code for the Vikunja client, POSTs it to Vikunja's
  `/api/v1/auth/openid/{provider}/callback`, and receives a Vikunja JWT plus a
  refresh-token cookie. It caches that session server-side and injects the
  bearer upstream on subsequent `Check` calls.

There is no separate upstream OP. This service is the identity authority for
Vikunja federation.

### Approach chosen: federator holds the session server-side

Three approaches were considered (see *Alternatives* below). The chosen design
is **Approach 1**: the federator owns the Vikunja session `(bearer,
refresh_cookie)` in a per-identity in-memory cache and injects the bearer into
the upstream request via `ext_authz` `OkHttpResponse.headers_to_add`. The
client never holds a Vikunja credential — it only needs the mTLS certificate.
This is uniform across browser, Android, and API clients with zero client-side
changes, and sidesteps the constraint that a gRPC `Check` response cannot
`Set-Cookie` on the client response.

### Clients served

Browser (Vikunja SPA), Android app, and raw API clients. All three present an
mTLS client certificate to Envoy; the federator handles them uniformly. If a
client additionally sends an `Authorization: Bearer <jwt>` and the local
verification fast-path is configured, the federator honors a valid incoming
bearer and allows the request through unchanged (the "check the request for an
existing token/cookie" intent). Otherwise it injects its own cached bearer.

## Settled by research

The following are pinned by research into Vikunja's auth model (Vikunja 2.0+,
source on `github.com/go-vikunja/vikunja`):

- **Access token**: short-lived JWT (default 10 min, `service.jwtttlshort`),
  HS256-signed with Vikunja's symmetric `service.secret`, conveyed as
  `Authorization: Bearer <jwt>`.
- **Refresh token**: `vikunja_refresh_token` cookie (`HttpOnly`, `Secure` when
  public URL is https, `SameSite=None`/`Lax`, `Path`-scoped to
  `/api/v1/user/token/refresh`), rotating, 72h idle TTL
  (`service.jwtttl`).
- **"Is this session valid?"**: `GET /api/v1/user` → 200 valid / 401 (`code: 11`)
  invalid. Vikunja's bearer auth is stateless — a logged-out JWT stays valid up
  to its 10-min `exp` — so local signature verification alone cannot detect
  logout. This design does **not** call `GET /api/v1/user` per request; it relies
  on local `exp` checks plus refresh/federation, with full re-federation as the
  fallback when refresh 401s.
- **Refresh**: `POST /api/v1/user/token/refresh` with the
  `Cookie: vikunja_refresh_token=<token>` header (no bearer) → `{"token":
  <new jwt>}` + rotated `Set-Cookie`. Single-use rotation; replaying an old
  cookie returns 401.
- **OIDC callback**: `POST /api/v1/auth/openid/{provider}/callback` with
  `{"code": <code>, "redirect_url": <url>}` → `200 {"token": <jwt>}` +
  `Set-Cookie`. This is the contract python-client-idp's broker already uses.
- **Local JWT verification**: possible only with Vikunja's `service.secret`
  (HS256 symmetric). It is an **optional fast-path** for incoming client
  bearers; it cannot detect logout, so it is never the sole source of truth for
  sessions we mint.

## Topology

```
user (mTLS cert) ──► envoy ──(ext_authz Check, peer cert)──► THIS service
                                                                │
                              ┌─────────────────────────────────┤
                              │ 1. verify mTLS cert (allow gate)│
                              │ 2. resolve stable sub + email   │
                              │ 3. session cache: reuse/refresh │
                              │    or federate (mint OP code →  │
                              │    POST Vikunja callback)       │
                              │ 4. inject Authorization: Bearer │
                              └─────────────────────────────────┘
envoy ◄──(OK + headers_to_add: Authorization: Bearer <jwt>)──────┘
  │
  └──► vikunja  (envoy forwards original request with the injected bearer;
                 THIS service is never in the data path)

                 THIS service (OP) ◄── discovery / /oauth/token / /jwks.json
                                       (Vikunja exchanges the code during
                                        federation)
```

- **User / initiator** — presents an mTLS client certificate to Envoy. May be a
  browser running the Vikunja SPA, the Android app, or a raw API client.
- **This service** — plays two roles:
  - Front door / federator: verifies the mTLS cert and federates to a Vikunja
    session, injecting the bearer upstream.
  - OIDC Provider: serves discovery, token, JWKS, userinfo so Vikunja can
    complete a standard authorization-code exchange during federation.
- **Vikunja** — an OIDC relying party / API. It delegates login to this OP via
  OIDC Discovery and exchanges an auth code for a Vikunja JWT.

There is no separate upstream OP. The federator is the identity authority.

## Architecture & components

The package stays `envoy_authz/`. New modules are grouped to keep each unit
single-purpose and independently testable, matching the existing flat-package
style. Each unit has one responsibility, a clear interface, and no hidden
coupling.

```
envoy_authz/
├── __init__.py            # JSON logging (unchanged)
├── __main__.py            # entrypoint; lifespan boots OP + federator stores
├── config.py             # Settings (pydantic-settings) + runtime Config container
├── grpc_service.py       # Check servicer; federation decision + header injection
├── http_app.py           # FastAPI factory; mounts the OP router
├── identity.py           # ClientIdentity (unchanged)
│
├── op/                   # NEW — OIDC Provider (ported from python-client-idp/app/idp)
│   ├── __init__.py        # init_op(app) — Starlette authlib AuthorizationServer wiring
│   ├── server.py         # AuthorizationServer + grant registration (Starlette flavor)
│   ├── grants.py         # AuthorizationCodeGrant / OpenIDCode / RefreshTokenGrant
│   ├── routes.py         # discovery, /jwks.json, /oauth/token, /oauth/userinfo (APIRouter)
│   └── keys.py           # RSA signing key load/generate, JWKS (ported; joserfc dep)
│
├── federator/            # NEW — session-reuse + federation engine
│   ├── __init__.py
│   ├── subject.py        # cert → stable subject (subject+SPKI fingerprint); email
│   ├── store.py          # OP-facing authlib store: clients/codes/tokens, query/save
│   ├── session.py        # per-identity SessionCache; get_bearer decision ladder
│   ├── vikunja.py        # Vikunja HTTP client: validate, refresh, federate (callback)
│   └── providers.py     # providers.yaml loader (ported; backend-agnostic)
│
└── providers.yaml        # NEW — downstream config (adapted from python-client-idp)
```

### Responsibility split

- **`op/`** — "be an OIDC Provider so Vikunja can do a standard code exchange."
  Depends only on authlib + `keys.py` + the store's `query_client`/`save_token`
  /code helpers. No knowledge of Envoy, mTLS, or Vikunja. Pure port of the
  source `app/idp/`, rewritten from Flask+authlib-flask to Starlette/FastAPI +
  authlib's Starlette integration (the grant classes are framework-agnostic;
  only the `AuthorizationServer` wiring changes). No `/oauth/authorize` route
  (the federator mints codes directly, same as the source broker).
- **`federator/subject.py`** — "turn a verified cert into a stable `sub` +
  email." Depends only on the `cryptography` cert. Pure function. Replaces the
  source's `get_or_create_user_by_email` in-memory counter with a deterministic
  derivation (subject + SPKI fingerprint) so a restart yields the same `sub` —
  Vikunja's user persists, and a changing `sub` would orphan it.
- **`federator/store.py`** — the authlib adapter layer (clients seeded from
  `providers.yaml`; stateless signed codes via itsdangerous). Ported from the
  source `app/store.py`, minus the broker-specific bits. Holds the in-memory
  `CLIENTS`/`TOKENS`/`REFRESH_TOKENS` dicts. There is **no persistent `USERS`
  dict**: subjects are derived deterministically in `subject.py`, so a `User`
  object is constructed on demand from the cert identity (email, name, stable
  `sub`) when the OP grant needs `request.user`. This removes the source's
  in-memory-counter `get_or_create_user_by_email` pattern.
- **`federator/session.py`** — "given an identity, return a valid Vikunja
  bearer, reusing/refreshing/federating as needed." The heart of Approach 1.
  Holds the per-identity `SessionCache` (in-memory). Depends on `vikunja.py`
  and `subject.py`. This is what `grpc_service.Check` calls.
- **`federator/vikunja.py`** — the Vikunja HTTP client: `refresh(cookie)` →
  `POST /api/v1/user/token/refresh`; `federate(identity)` → mint OP code + POST
  callback (the source's `mint_downstream_token`). Depends on `op/store` (to
  mint the code) + `providers`. Uses `httpx` (promoted from dev to runtime;
  async-capable, already in the tree). The source used `niquests`; this port
  uses `httpx`. The verbatim `Set-Cookie` extraction logic (handling the
  comma-bearing `Expires` case) carries over. There is intentionally **no
  `GET /api/v1/user` validation call on the hot path** — the decision ladder
  relies on local `exp` checks plus refresh/federation, so Vikunja is only
  reached on the cold/stale paths (refresh, federation). A `validate(bearer)`
  helper is not built (YAGNI); if strict per-request session validity is ever
  needed, it would be added then.
- **`federator/providers.py`** — verbatim port of the source `app/providers.py`
  (Pydantic + `${VAR}`/`${VAR:-default}` interpolation). Single source of truth
  per downstream backend.
- **`grpc_service.py`** — gains one new step after the allow gate: call
  `session.get_bearer(identity, incoming_bearer)` and, if it returns a bearer,
  append an `Authorization: Bearer` `HeaderValueOption` to
  `OkHttpResponse.headers_to_add`. The Frigate `X-Proxy-Secret` path is
  untouched. On federation failure, returns `PERMISSION_DENIED` (deny rather
  than let an unauthenticated request reach Vikunja).
- **`http_app.py`** — `create_app` now also calls `init_op(app)` to mount the OP
  `APIRouter`. `/healthz` stays.
- **`__main__.py` lifespan** — now also loads providers, seeds the OP store,
  loads/generates the RSA key, and constructs the `SessionCache` + Vikunja
  client, passing them into the gRPC servicer (which already receives `Config`)
  and stashing on `app.state`.

### Deliberately not ported

The Flask `broker/` blueprints and `http_debug.py` from python-client-idp —
their job is now `federator/session.py` + `vikunja.py`, triggered by gRPC, not
an HTTP route. And `niquests` → `httpx`.

## Config & settings

The existing plain `Config` dataclass + `os.environ` reads are replaced with a
pydantic-settings `BaseSettings` model. This is an in-scope refactor (the
config is growing substantially and benefits from validation), not unrelated
cleanup. Required fields fail fast at startup with a clear error; `SecretStr`
prevents accidental logging of secrets; types are coerced/validated; `.env`
loading is built in.

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    # --- existing (preserved) ---
    frigate_x_proxy_secret: SecretStr
    ha_ca_certificate: str                      # PEM
    ha_crl: str | None = None                    # PEM

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
```

The four `os.environ.get(...)` reads in `__main__.py` collapse into the same
settings object.

**Derived/runtime state stays separate from `Settings`:** the `ha_ca_store`
(`X509Store`) is built from `ha_ca_certificate`/`ha_crl` at startup, not a
settings field — it is runtime state, not config. Similarly the loaded
`providers` dict, the OP store, the RSA key, and the `SessionCache` are
constructed in the lifespan. The lifespan builds: `Settings` → `Config` (a
small runtime container holding `settings` + the built `ha_ca_store` +
`providers` + cache + key). That `Config` is passed to the gRPC servicer and
stashed on `app.state`. This keeps declared config and constructed runtime
state cleanly separated.

**Env-var name mapping:** pydantic-settings maps `frigate_x_proxy_secret` →
`FRIGATE_X_PROXY_SECRET`, `ha_ca_certificate` → `HA_CA_CERTIFICATE`, `ha_crl`
→ `HA_CRL`, `grpc_port` → `GRPC_PORT`, etc. The existing names are preserved, so
no k8s manifest env changes are required for the existing fields.

### Per-backend session secret in `providers.yaml`

The Vikunja `service.secret` (HS256) is per-backend, so it lives in
`providers.yaml` next to that backend's other config, not as a top-level
setting. The `Provider` model gains a generic `extra` field for
backend-specific config:

```yaml
providers:
  vikunja:
    client_id: "${VIKUNJA_CLIENT_ID:-vikunja}"
    client_secret: "${VIKUNJA_CLIENT_SECRET:-vikunja-secret}"
    redirect_url: "${VIKUNJA_REDIRECT_URL:-http://localhost:3456/auth/openid/broker}"
    api_base: "${VIKUNJA_API_BASE:-http://localhost:3456}"
    provider_key: "${VIKUNJA_PROVIDER_KEY:-broker}"
    scope: "openid profile email"
    extra:
      session_secret: "${VIKUNJA_SESSION_SECRET:-}"   # Vikunja service.secret (HS256); optional
```

```python
class Provider(BaseModel):
    client_id: str
    client_secret: str
    redirect_url: str
    api_base: str
    provider_key: str
    scope: str = "openid profile email"
    extra: dict[str, str] = {}      # backend-specific config; Vikunja: session_secret
```

A generic `extra` dict keeps `Provider` backend-agnostic (the source design's
stated intent). The Vikunja client reads `provider.extra.get("session_secret")`
at construction; if present, it can verify an incoming bearer's HS256 signature
+ `exp` offline before trusting it; if absent, it treats incoming bearers as
opaque and relies on the cached session. Other backends would read their own
keys.

**Trade-off:** `extra: dict[str, str]` is untyped — a typo like
`session_secert` fails silently (no local fast-path, falls back to
refresh/federation, which still works correctly, just slower). This is an
acceptable, fail-safe degradation. The upgrade path if validation is later
wanted is a per-backend config model (e.g. a `VikunjaExtra` Pydantic model
selected by a `type: vikunja` discriminator); YAGNI until a second backend
exists.

## Data flow & the session cache

The `SessionCache` (`federator/session.py`) holds the per-identity Vikunja
session server-side. The gRPC `Check` path consults it on every request.

**Cache shape** — keyed by the stable `sub`:

```python
@dataclass
class CachedSession:
    bearer: str                 # Vikunja JWT, short-lived (~10 min)
    refresh_cookie: str | None  # vikunja_refresh_token value (rotates on refresh)
    exp: float                  # bearer exp (unix); when we must refresh
    user_id: str | None         # decoded from the bearer JWT payload, for logging
```

In-memory `dict[str, CachedSession]` with per-key locking (the gRPC thread pool
has 4 workers; refresh/federation are blocking I/O and must not corrupt the
dict or double-federate concurrently for the same identity).

**The decision ladder in `session.get_bearer(identity, incoming_bearer)`, called
by `Check` after the cert allow-gate:**

```
1. incoming_bearer present?
   - If session_secret configured: verify HS256 sig + exp locally, AND that the
     token is a Vikunja *user* token (`type`) whose `id` is the Vikunja user this
     mTLS subject already maps to (CachedSession.user_id).
     - valid, bound & not near-expiry → return None  (allow through unchanged)
     - valid but near-expiry          → fall to step 2 (inject a fresh one upstream)
     - wrong user / wrong type / no known mapping → fall to step 2 (never trusted)
   - If no session_secret: treat as opaque; can't trust it locally.
     → fall to step 2 (use the cached session)
   (Honoring a verified client bearer is the "check the request" intent;
    if we can't verify it, we don't trust it.)

   NOTE (corrected): an earlier revision of this spec required only "verify HS256
   sig + exp". That is NOT sufficient and was implemented as specified before
   being caught in review. A valid signature does not identify a user: Vikunja
   signs link-share tokens with the same `service.secret` and hands them to anyone
   holding a public share hash, and any user's token verifies equally well. Under
   the old rule a cert holder could present ANOTHER user's bearer and be passed
   through as them, making the mTLS identity — the whole point of the gate —
   irrelevant on this branch. The `id`/`type` binding above is required.

2. cached = cache[sub]
   - cached and cached.exp > now + margin → return cached.bearer  (inject upstream)
   - cached and stale (exp near) → refresh (step 3)
   - no cache → federate (step 4)

3. refresh: POST /api/v1/user/token/refresh  (Cookie: vikunja_refresh_token=<cached>)
   - 200 → new {token} + rotated Set-Cookie → update cache → return new bearer
   - 401 (session revoked/expired) → federate (step 4)
   - network error → raise (Check denies)

4. federate: mint stateless OP auth code → POST /api/v1/auth/openid/<provider_key>/callback
            {code, redirect_url} → 200 {"token": <jwt>} + Set-Cookie
   - 200 → cache (bearer, cookie, exp) → return bearer
   - failure → raise (Check denies)
```

**Return contract to `Check`:** `get_bearer` returns `str | None`:
- `None` → "no injection needed" (client's incoming bearer was valid; `Check`
  allows through unchanged). The only path where `Check` does *not* add an
  `Authorization` header.
- `str` → "inject this bearer upstream" (`Check` appends `Authorization: Bearer
  <str>` to `OkHttpResponse.headers_to_add`).

**Concurrency:** a per-key lock (dict of locks) serializes refresh/federation
for a single identity so two simultaneous `Check`s for the same user don't
double-federate (which would mint two codes and rotate the cookie out from
under one another). Other identities proceed independently; no global
bottleneck.

**Expiry margins:** `exp` is decoded from the bearer JWT. Refresh is triggered
`margin` seconds before `exp` (default ~60s) so the injected bearer isn't
already-expired by the time it reaches Vikunja.

**The no-`session_secret` case:** without Vikunja's HS256 secret we cannot
verify an *incoming client* bearer, so we never trust it (step 1 falls through;
we rely on our cached session). For the *cached* session (one we minted over a
trusted channel), we decode `exp` from the JWT payload we received from
Vikunja's callback — trusting our own obtained token's payload, no signature
check needed. So `CachedSession.exp` is always populated. The local fast-path on
*incoming* bearers exists only when `session_secret` is configured; without it
the federator always injects its own cached bearer. This is the correct, safe
behavior.

The fast path additionally requires an established `sub` → Vikunja-user mapping
to bind against (see step 1). Before the first federation there is no mapping, so
an incoming bearer is not trusted and we fall through — fail-closed by default.

**Restart behavior:** the in-memory cache is lost on restart. The first request
after restart has no cache and federates (step 4). The stable `sub` means
Vikunja re-resolves the same user (no orphaning). Acceptable at single-replica
scale; flagged as a known limitation.

## Error handling, failure modes & observability

**Failure → deny.** Every federation/refresh failure path raises; `Check`
catches and returns `PERMISSION_DENIED` with the existing `{"error":
"Unauthorized"}` body. The request never reaches Vikunja without a valid
bearer.

| Failure | Where | Handling |
|---|---|---|
| No/invalid client cert | `verify_client_cert` | Deny (unchanged allow gate) |
| Vikunja unreachable on refresh | `vikunja.refresh` | Raise → deny; log `warning` (provider + identity) |
| Vikunja unreachable on callback | `vikunja.federate` | Raise → deny; log `error` |
| Refresh 401 (session revoked/expired) | `vikunja.refresh` | Not an error — fall through to federation. Log `info` (expected churn) |
| Callback non-200 / no `token` | `vikunja.federate` | Raise `DownstreamError` → deny; log `error` (status + truncated body) |
| OP code mint fails | `store.create_authorization_code` | Raise → deny (pure signing; shouldn't happen) |
| Callback returns token but no `Set-Cookie` | `vikunja.federate` | Cache bearer with `refresh_cookie=None`; future refresh 401s → re-federate. Log `warning` |
| Concurrent refresh for same identity | session lock | Serialized per-key; second caller waits and reuses the first's result |
| `providers.yaml` missing / bad | startup | Fatal (consistent with source `load_providers`) |
| Missing required `Settings` field | startup | Fatal — pydantic ValidationError, clear message |

**Timeouts.** All Vikunja calls (refresh, callback) use a bounded timeout (httpx,
~10s, matching the source). A hung Vikunja denies after the timeout rather than
hanging Envoy's request. `GET /api/v1/user` validation is not called per
request in steady state (local `exp` + refresh); only refresh/federation hit
Vikunja.

**Observability — structured JSON logging (existing logger):**
- Every `Check` logs the existing request line (host, path, principal) plus the
  identity and the **decision branch taken** (`allowed-through-client-bearer` /
  `injected-cached` / `injected-refreshed` / `injected-federated` /
  `denied-no-cert` / `denied-federation-failure`). The federation state machine
  is observable in logs.
- Refresh/federation/failure events log `provider`, `sub`, and the Vikunja
  response status.
- No new metrics endpoint (YAGNI; `/healthz` stays). A future Prometheus project
  is out of scope.

**No secrets in logs.** `secret_key`, `frigate_x_proxy_secret`, client secrets,
and `session_secret` are `SecretStr` / never logged. Bearer tokens and refresh
cookies are never logged — only the branch + status.

**Vikunja 5xx on an injected-bearer request** is outside the federator: Envoy
forwards to Vikunja and Vikunja responds. The federator's job ends at "inject a
valid bearer"; it does not proxy the data path (the source spec's "mode a").

## Testing

The existing harness — ephemeral PKI fixtures (`tests/conftest.py`) and
real-TLS gRPC + FastAPI `TestClient` patterns — is extended.

1. **Unit — `subject.py`**: deterministic `sub` derivation (stable across
   calls/restarts); email extraction. Pure function.
2. **Unit — `op/` (port correctness)**: discovery shape, JWKS, auth-code →
   id_token (RS256, `iss`/`aud`/`sub`), userinfo with bearer, refresh-token
   rotation, PKCE positive/negative. Ported from source `tests/test_idp.py`,
   minting codes directly. Verifies the Flask→Starlette port didn't change OP
   behavior.
3. **Unit — `vikunja.py`**: against a fake Vikunja (`respx`). Covers callback
   `{code, redirect_url}` → `{"token"}` + verbatim `Set-Cookie` extraction
   (including comma-bearing `Expires`); refresh 200 → rotated cookie; refresh
   401 → "session expired" sentinel; callback non-200 / no token →
   `DownstreamError`; timeouts.
4. **Unit — `session.py` (decision ladder)**: with `vikunja.py` mocked. Every
   branch: incoming valid+fresh bearer (with `session_secret`) → `None`;
   incoming near-expiry → cache; cached fresh → cached bearer; cached stale →
   refresh → new bearer, cache updated; refresh 401 → federate; no cache →
   federate; refresh network failure → raises; federate failure → raises; no
   `session_secret` + incoming bearer → not trusted → cache; concurrent
   same-identity → single callback call.
5. **Unit — `grpc_service.Check` integration**: existing `grpc_server`/`stub`/
   `check_request` fixtures with `get_bearer` mocked. Valid cert + cached
   bearer → `OK` with `Authorization: Bearer` header; valid cert + `None` →
   `OK` with no `Authorization` header; federation failure →
   `PERMISSION_DENIED`; Frigate path still injects `X-Proxy-Secret`
   (regression).
6. **Unit — `Settings`**: required fields fail fast; env-name mapping preserves
   `FRIGATE_X_PROXY_SECRET`/`HA_CA_CERTIFICATE`/`HA_CRL`/ports; `SecretStr`
   fields don't leak in repr. Replaces existing `test_setup.py` assertions.
7. **Integration — providers config**: `providers.yaml` parsing, `${VAR}`/
   `${VAR:-default}` interpolation, schema validation (ported `test_providers.py`).
8. **Integration — live Vikunja** (`@pytest.mark.integration`, auto-skip if
   unreachable): broker + Vikunja via docker-compose; present a client cert;
   assert a bearer is minted and authenticates against `GET /api/v1/user`; a
   second request reuses the cached session (no second callback); simulate
   cache expiry → refresh → reuse.

**New dev deps:** `respx` (httpx mocking). `integration` pytest marker added
to pyproject (this repo doesn't have it yet).

**docker-compose** for the integration test: adapted from python-client-idp's
(broker = this service + Vikunja, `IDP_ISSUER`, inter-service in-cluster http).
The existing `k8s.yaml` stays the deployment target; compose is test-only.

**Not tested (YAGNI):** multi-replica cache coherence, Prometheus metrics, the
OP authorize browser flow, dynamic client registration, a second downstream
backend, per-request `GET /api/v1/user` validation.

## Porting plan & build sequence

Each step is independently testable and committable.

1. **Prep: dependencies & config refactor.** Promote `httpx` dev→runtime. Add
   `pydantic-settings`, `authlib`, `joserfc` (explicit — the source relied on
   it transitively via authlib; avoid the latent packaging hazard), `pyyaml`,
   `itsdangerous` as runtime deps. Add `respx` + `integration` marker to dev.
   Refactor `config.py` → pydantic-settings `Settings` + runtime `Config`
   container; update `__main__.py` and `test_setup.py`. All existing tests pass.
2. **Providers config.** Port `providers.py` + `providers.yaml` (with
   `extra.session_secret`) and `tests/test_providers.py`.
3. **Subject derivation.** `federator/subject.py` + unit tests.
4. **The OP (Flask→Starlette port).** `op/keys.py`, `op/server.py`,
   `op/grants.py`, `op/routes.py`, `op/__init__.py`, and the OP-facing half of
   `federator/store.py`. Mount via `http_app.create_app` → `init_op`. Port
   `tests/test_idp.py`/`test_keys.py`/`test_store.py`. After this step the
   service is a working OP with no federation yet.
5. **Vikunja client.** `federator/vikunja.py` (`validate`, `refresh`,
   `federate`, ported to httpx with verbatim `Set-Cookie` extraction). Unit
   tests with `respx`.
6. **Session cache + decision ladder.** `federator/session.py` (`SessionCache`,
   `get_bearer`, per-key locking). Unit tests for every branch.
7. **gRPC `Check` integration.** Wire `session.get_bearer` into
   `AuthorizationService.Check` after the allow gate; inject `Authorization:
   Bearer` via `headers_to_add`; deny-on-failure. Unit tests via existing gRPC
   fixtures with `get_bearer` mocked. Frigate regression test.
8. **Lifespan wiring.** `__main__.py` lifespan constructs providers, OP store,
   RSA key, `SessionCache`, Vikunja client; passes into the servicer; stashes on
   `app.state`. Update `test_main.py`.
9. **Live integration test.** `docker-compose.yml` (test-only) +
   `tests/test_integration_vikunja.py` (marked, auto-skips).
10. **Docs.** Fill the empty `README.md` with the architecture (two servers,
    shared config, mTLS-then-federate flow, config table). Deployment notes for
    new env vars (`IDP_ISSUER`, `SECRET_KEY`, `PROVIDERS_FILE`,
    `VIKUNJA_SESSION_SECRET` in providers.yaml) and k8s manifest/ExternalSecrets
    additions (OP signing key, Vikunja client secret, session secret).

**Branch strategy:** feature branch off `main`, PR per the repo's PR-based
workflow. This build sequence becomes the implementation plan's task breakdown.

## Alternatives considered

- **Approach 1 (chosen) — federator holds the session server-side; injects
  bearer upstream.** The federator caches `(bearer, refresh_cookie)` per mTLS
  identity in memory; on `Check` it injects the bearer via
  `OkHttpResponse.headers_to_add`. Uniform across browser/Android/API with
  zero client changes; no `Set-Cookie` problem; fast hot path (local exp-check,
  no Vikunja call per request). Stateful (in-memory; restart re-federates —
  acceptable at single-replica). "Check the request for an existing token"
  becomes a vestigial fast-path since the client usually carries no token.
- **Approach 2 — client holds the session; deliver via direct response on
  `Check`.** Federation/refresh returns a `DeniedHttpResponse` (307 +
  `Set-Cookie` + `Location`); the client stores the cookie and retries. Matches
  "pass cookies back to the user" literally and can be stateless, but every
  refresh costs an extra redirect; "deny to allow" is semantically awkward;
  Vikunja's refresh-cookie `Path` must be preserved exactly; raw API clients
  must follow redirects + keep a cookie jar. Most complex on the wire. Set
  aside.
- **Approach 3 — hybrid: HTTP login endpoint delivers cookies; gRPC `Check`
  validates + injects.** A `/auth/federate` HTTP endpoint (Envoy forwards the
  mTLS cert) federates once and `Set-Cookie`s the client; the gRPC `Check`
  path validates the incoming bearer, injects via `headers_to_add`, refreshes
  server-side when stale. Clean separation; client owns a real session
  (survives restart); works for all client types. Most surface to build; clients
  need a bootstrapping step (or Envoy redirects 401s there). Preferred if
  client-owned sessions were a hard requirement.

Approach 1 was chosen for the best fit with the gRPC-`Check`-triggered model:
uniform across clients, sidesteps the gRPC-can't-`Set-Cookie` constraint, fast
hot path, benign statefulness at single-replica scale.

## Out of scope (YAGNI)

- Multi-replica shared cache (Redis) — single-replica today.
- Prometheus metrics — `/healthz` stays; metrics are a separate project.
- The OP `/oauth/authorize` browser flow — no such route (same as source).
- Dynamic client registration (RFC 7591).
- A second downstream backend — `Provider` config is keyed to allow it, but
  only Vikunja is wired.
- Per-request `GET /api/v1/user` validation — we rely on local `exp` +
  refresh/federation.
- Client-side changes — Approach 1 needs none.
- Replacing httpx for the `TestClient` backend — httpx stays as the Starlette
  `TestClient` transport; the federator's Vikunja HTTP client also uses httpx.

## Known limitations

- **In-memory session cache** is lost on restart; the first request after
  restart federates. The stable `sub` means Vikunja re-resolves the same user.
- **Local JWT verification cannot detect logout.** When `session_secret` is
  configured, an incoming bearer is verified for signature + `exp` only; a
  logged-out-but-not-yet-expired Vikunja JWT (≤10 min) would still be honored.
  This matches Vikunja's own stateless bearer semantics.
- **`extra` config is untyped.** A typo in a backend-specific key (e.g.
  `session_secret`) fails silently to a safe-but-slower fallback.
- **Single replica.** The deployment is single-replica; the per-identity cache
  is not shared across instances. Multi-replica needs a shared store (Redis),
  out of scope here.