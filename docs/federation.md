# mTLS → OAuth2 Federation

This service is an Envoy **external authorization** (ext_authz) gRPC server that
adds an OAuth2/OIDC **federation** layer on top of the existing mTLS + Frigate
proxy-secret authorization.

## Topology

```
                ┌──────────┐   mTLS (client cert)    ┌──────────────────────┐
   client ────▶ │  Envoy   │ ─────────────────────▶  │  ext_authz (this)    │
 (browser/app)  │ (L7)     │   gRPC Check            │  AuthorizationService│
                └────┬─────┘                         └─────────┬────────────┘
                     │                                         │ get_bearer()
                     │  (on allow) injects                      │
                     │  Authorization: Bearer … upstream        ▼
                     │                              ┌──────────────────────┐
                     └─────────────────────────────▶│  Vikunja (downstream)│
                                                    └──────────────────────┘
```

(The `ext_authz` box also hosts the OP. After the federator mints an OP auth
code, Vikunja redeems it back at this service's `/oauth/token` to mint its own
id/access token — the diagram drops that return call for clarity.)

Envoy terminates the client mTLS certificate and forwards the verified cert PEM
(URL-encoded) in `attributes.source.certificate`. On each `Check`:

1. The service verifies the cert against the configured HA CA (+ CRL) and
   demands the `clientAuth` EKU.
2. On the **Frigate path** (`host == FRIGATE_HOST`) the existing behavior holds:
   inject `X-Proxy-Secret`. Federation does **not** run there.
3. If a provider **claims** the request host (its `hosts` allowlist, see
   `providers.yaml`), the service derives a stable subject from the cert, then:
   - Vikunja's **own OIDC paths** (the frontend callback route and the backend
     endpoint that redeems a code) pass through **untouched** — see
     [Browser bootstrap](#browser-bootstrap-document-navigations) below.
   - A **document navigation** (a real browser address-bar/link hit, not an
     API/XHR call) gets the browser-bootstrap `denied_response` instead of the
     silent ladder — see below.
   - Everything else **federates**: it runs the `get_bearer` decision ladder,
     and either injects `Authorization: Bearer <token>` upstream, lets the
     client's own bearer through unchanged, or denies.
4. Any other allowed host passes through with **no header**. Host scoping is
   an allowlist on purpose: attaching this ext_authz to a new vhost must not
   silently start injecting some other backend's bearer over the client's own
   credential.

## Browser bootstrap (document navigations)

`get_bearer` attaches its `Authorization` header to the request Envoy forwards
*upstream* — invisible to a browser's own JS. A browser SPA hitting Vikunja
directly never becomes "logged in" from that alone: it still falls
through to Vikunja's own client-side OIDC login, which redirects to this
service's OP `authorization_endpoint` — a route that does not exist (see
`op/routes.py`: the OP mints codes server-to-server only, by design).

Reconciling this without any Envoy/Contour changes: `envoy_authz.federator.
browser_bootstrap` detects a top-level navigation (`Sec-Fetch-Dest: document`,
falling back to `Accept: text/html`) to a federated host and, instead of the
silent ladder, denies with an HTTP **200** whose body is a small page that
does exactly what Vikunja's own "Login with `<provider>`" button would have:
stores a `state` in `localStorage`, then navigates to Vikunja's callback route
with a code this service already minted (`store.create_authorization_code`,
the same call `federate()` uses). The caller fully controls
`DeniedHttpResponse.status`/`headers`/`body` — Envoy sends them straight to the
browser without ever proxying that hit to Vikunja — so this replicates
Vikunja's real, CSRF-checked front-channel flow (`OpenIdAuth.vue` hard-fails on
a `state` mismatch, so a bare server-side redirect that skipped setting it first
would not work).

The exchange breaks unless two paths stay exempt from this (and from the
ladder): `frontend_oidc_path(provider)` (the callback page the bootstrap script
navigates to) and `vikunja.callback_path(provider)` (the API call that page
makes to redeem the code) always pass through untouched.

No server-side signal reveals whether a browser already holds a valid Vikunja
JWT, so this runs on **every** document navigation to a federated host, not just
the first. That is intentional, not a cache miss: this whole model derives a
session from the mTLS cert per request, so a full page reload legitimately
re-deriving a fresh one stays consistent with treating "logout" as meaningless
while the client keeps presenting the cert.

## Native app OAuth (authorization-code + PKCE)

The browser bootstrap logs Vikunja's *web frontend* in. The native app
(`vikunja-flutter`) instead runs a standard OAuth **authorization-code + PKCE**
login against the public URL, and must never see the downstream OIDC handshake
— only its own code and tokens. `envoy_authz.federator.app_oauth` synthesizes
both legs entirely from the mTLS identity (`grpc_service.Check` answers each
with a `denied_response`, so neither hit reaches Vikunja):

- **`GET /oauth/authorize`** (matched by `client_id=vikunja-flutter`, checked
  *before* the browser-bootstrap branch since that GET is itself a
  document navigation): validates `response_type=code`, the `redirect_uri`
  allowlist and an S256 `code_challenge`, mints a **subject-bound** PKCE code
  (`store.create_authorization_code`, `user_id=subject.sub`), and denies with a
  **302** straight to `vikunja-flutter://callback?code=…&state=…`. The browser
  follows the custom-scheme redirect back into the app; no Vikunja page renders.
- **`POST …/oauth/token`** (matched by `client_id` in the body): reads the body
  (see the `with_request_body` note below), verifies the code
  (signature, TTL, single use), the `redirect_uri`, PKCE, and that the **same
  certificate subject** redeems it, then federates server-side
  (`vikunja.federate`) and returns the Vikunja bearer as
  `{access_token, token_type, expires_in, refresh_token}`. `grant_type=
  refresh_token` (also subject-bound) re-federates for a fresh bearer. The app
  posts this body as **JSON** (`Content-Type: application/json`), not the RFC
  6749 form encoding, so the body parser honours the Content-Type and accepts
  either.

Security note: the whole exchange runs over mutually-authenticated TLS, so the
real principal on both legs is the client certificate. Binding the code and
refresh token to `subject.sub` — refusing them to any other certificate — is
what makes this safe for this transport; PKCE verification adds a further check.

> **Deployment note:** the token/refresh bodies arrive in the POST body,
> which an ext_authz filter forwards to `Check` only with
> [`with_request_body`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto)
> configured (`max_request_bytes` ≥ a few KiB, `pack_as_bytes: false`). Without
> it the body arrives empty, nothing matches the token leg, and the request
> falls through to Vikunja (which 404s it). Set this on the edge Envoy/Contour
> ext_authz filter in every environment that serves the native app.

## The `get_bearer` decision ladder

Per request, for a derived `Subject` (`sub` is a 16-char SHA-256 of the cert's
subject DN DER + SubjectPublicKeyInfo DER):

1. **Incoming bearer present?** With a `session_secret` present, verify the
   bearer's HS256 signature + `exp` locally **and** check that the token is a
   Vikunja *user* token (`type`) belonging to the Vikunja user this mTLS subject
   already maps to. Valid, bound and not near-expiry → **allow through
   unchanged** (return `None`, no `Authorization` header). Otherwise → fall to
   step 2.

   The binding matters: Vikunja signs link-share tokens with the same
   `service.secret` and hands them out to anyone with a public share hash, so a
   valid signature alone does not identify a user. Without the `id`/`type` check
   a cert holder could present *another* user's bearer, and Vikunja would serve
   them as that user — making the mTLS identity irrelevant on this branch.
2. **Cached session?** A per-identity in-memory cache keyed by `sub`. A fresh
   cached entry → inject its bearer. A stale entry with a refresh cookie →
   step 3. A stale entry without a refresh cookie, or no cache → step 4.
3. **Refresh** (`POST /api/v1/user/token/refresh` with the refresh cookie):
   `200` → rotate, cache, inject. `401` (revoked) or any other **terminal**
   failure → drop the cache entry and fall through to step 4, so it never
   retries a permanently dead cookie forever. Transport error / `5xx` → deny
   (503), keeping the entry (its cookie is probably still good).
4. **Federate** (mint an OP auth code, `POST {code, redirect_url}` to Vikunja's
   OpenID callback): `200` → cache, inject. Failure → deny.

Steps 3 and 4 both run under a **per-identity lock**, so concurrent requests for
one user neither double-federate nor race on Vikunja's single-use refresh cookie.
Locks use a fixed-size striped array, and expiry plus a max-entry cap bound the
session cache.

**The hot path never calls Vikunja**: it decides validity locally via `exp` and
the cache; only the cold paths (refresh/federate) reach Vikunja, and it issues
no per-request `GET /api/v1/user`.

## Return contract

This ladder only runs for non-navigation requests (see
[Browser bootstrap](#browser-bootstrap-document-navigations) above for how the
OP handles a real browser page load instead):

| `get_bearer` result | `Check` response |
|---|---|
| `str` | `OK` + `headers: Authorization: Bearer <str>` (upstream request only) |
| `None` | `OK` with **no** `Authorization` header (client's bearer allowed through) |
| raises `DownstreamError` | deny |

**Deny status policy:**

- `retryable=True` (Vikunja unreachable / `5xx`) → `PERMISSION_DENIED` +
  HTTP **503 Unavailable** (clients may retry).
- `retryable=False` (terminal `4xx`) → `PERMISSION_DENIED` + HTTP **401 Unauthorized**.
- Both carry the body `{"error": "Unauthorized"}`.

> Note: the pre-existing Frigate/mTLS deny path still uses **403 Forbidden**;
> aligning it with this 401/503 scheme is a possible future change.

## The OAuth2/OIDC Provider (OP)

Vikunja redeems the federation auth code at **our** OP token endpoint itself.
The OP is a FastAPI router mounted at the app root; at startup it loads or
creates the RSA signing key from `OP_KEY_PATH`, and discovery advertises
`IDP_ISSUER` as the issuer:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery (issuer, endpoints, `RS256`, PKCE `S256`/`plain`) |
| `GET /jwks.json` | Public signing key (`kid`, RS256) |
| `POST /oauth/token` | Auth-code → `{access_token, id_token, refresh_token}`; refresh rotation |
| `GET/POST /oauth/userinfo` | Scoped `sub`/`name`/`email` for a bearer |

Auth codes stay **stateless** (`itsdangerous` signed, short TTL): `email`/`name`
travel inside the signed payload, so the OP keeps no `USERS` store —
`authenticate_user` reconstructs the user from the code/token payload. Each code
carries a `jti` that the OP records on redemption (RFC 6749 §4.1.2) to keep it
**single-use** within its TTL.

**Access and refresh tokens stay stateless too — a hard rule for running more
than one OP replica.** A round-robin Service fronts the OP, so Vikunja's
`POST /oauth/token` and its follow-up `GET /oauth/userinfo` routinely land on
*different* replicas. An opaque token kept in one process's dict means nothing
to the other replica, which answers userinfo with `401 invalid_token` — and
Vikunja turns that into a `500` on its openid callback, so federation fails
intermittently (roughly per the load-balancer split). Instead,
`store.create_access_token` / `create_op_refresh_token` mint signed,
self-contained blobs (distinct `itsdangerous` salts, one shared `SECRET_KEY`);
`query_token` and the refresh grant **reconstruct** the record from the signed
payload — a signature + TTL check with no shared state — so a token minted on
one replica validates on every replica. `save_token` does nothing.

Tradeoff, matching the native-app refresh token: the OP refresh token carries
**no server-side revocation** (a shared revocation table is exactly the
per-replica state this avoids). Rotation still hands back a fresh token, but the
previous one keeps working until its TTL. The auth-code single-use `jti` set
still lives per-replica in memory, so single-use holds within one replica; the
short code TTL, plus the fact that codes travel only server-to-server over
in-cluster TLS, bounds replay across replicas.

## `providers.yaml`

Each entry is one downstream backend the federator can federate to. Values may
reference the environment as `${VAR}` or `${VAR:-default}` (an undefined
`${VAR}` with no default is a fatal startup error).

A variable that is **unset or empty** falls back to its default (an empty k8s
secret value is a missing secret, not a deliberate empty one); with no default,
unset-or-empty is a fatal startup error. Use `${VAR:-}` to opt into empty.
Secrets deliberately carry **no default** — a missing injection must fail
startup rather than silently fall back to a value published in this repo.

`hosts` is the allowlist of Envoy request hosts this backend federates for.

```yaml
providers:
  vikunja:
    hosts:
      - "${VIKUNJA_HOST:-vikunja.apps.somemissing.info}"
    client_id: "${VIKUNJA_CLIENT_ID:-vikunja}"
    client_secret: "${VIKUNJA_CLIENT_SECRET}"   # no default: inject it
    redirect_url: "${VIKUNJA_REDIRECT_URL:-http://localhost:3456/auth/openid/broker}"
    api_base: "${VIKUNJA_API_BASE:-http://localhost:3456}"
    provider_key: "${VIKUNJA_PROVIDER_KEY:-broker}"
    scope: "openid profile email"
    extra:
      # Vikunja service.secret (HS256). When present, the federator verifies an
      # incoming bearer's signature + exp locally before trusting it. When
      # absent, the federator treats incoming bearers as opaque (cache is used).
      session_secret: "${VIKUNJA_SESSION_SECRET:-}"
```

The callback URL is `{api_base}/api/v1/auth/openid/{provider_key}/callback`,
which `vikunja.federate` builds (the wire contract lives with the client).

## Configuration (environment)

All config is env-driven (`pydantic-settings`). Secrets are `SecretStr` and
never leak in repr/logs.

| Variable | Default | Purpose |
|---|---|---|
| `FRIGATE_X_PROXY_SECRET` | *(required)* | Frigate proxy secret |
| `HA_CA_CERTIFICATE` | *(required)* | mTLS client-cert CA PEM |
| `HA_CRL` | *(unset)* | CRL PEM (optional) |
| `IDP_ISSUER` | *(unset)* | OP issuer URL. Required **to enable federation** |
| `SECRET_KEY` | *(unset)* | Signs stateless OP auth codes (`itsdangerous`). Required to enable federation |
| `PROVIDERS_FILE` | *(unset)* | Path to providers config. Required to enable federation |
| `OP_KEY_PATH` | `op_key.pem` | OP RSA signing key (load-or-create, persisted) |
| `CODE_TTL_SECONDS` | `10` | Stateless auth-code TTL |
| `GRPC_PORT` | `5000` | ext_authz gRPC port |
| `HTTP_PORT` | `5001` | OP HTTPS port |
| `TLS_CERT_PATH` | `/var/lib/tls/tls.crt` | gRPC server TLS cert |
| `TLS_KEY_PATH` | `/var/lib/tls/tls.key` | gRPC server TLS key |

**Federation is opt-in.** The service enables it only when you set all three of
`IDP_ISSUER`, `SECRET_KEY` and `PROVIDERS_FILE`. Missing any one, the service
logs `Federation disabled …`, mounts no OP, wires no federator, and behaves
exactly as it did before this layer existed — the mTLS allow gate plus the
Frigate `X-Proxy-Secret`. That keeps the existing k8s manifest (which carries
only `FRIGATE_X_PROXY_SECRET` and `HA_CA_CERTIFICATE`) valid: it keeps
deploying and running unchanged, with federation off until you add those vars.

`PROVIDERS_FILE` has no usable default: the shipped file lives at
`envoy_authz/providers.yaml` inside the package, which does not match the
container's working directory, so you must give the path explicitly (the compose
stack mounts it at `/etc/envoy-authz/providers.yaml`).

## Security notes

- **Bearer tokens and refresh cookies never reach the log.** Log lines carry
  only the subject `sub` and the decision branch.
- **No bearer signature check on tokens we get ourselves** — we trust the token
  from our own channel to Vikunja and read only `exp`/`id`. The service trusts
  an *incoming client* bearer only when `session_secret` is present and its
  HS256 signature + `exp` verify locally.
- The federator copies refresh-token cookies verbatim from `Set-Cookie`,
  including the comma-bearing `Expires` case.
- Per-identity locking prevents concurrent same-user double-federation **and**
  refresh-cookie races; the federator caches sessions server-side (bounded) and
  injects them upstream via ext_authz `headers`.
- **The OP writes the signing key `0600`** in a `0700` directory, and tightens
  an existing key with looser bits on load. The key stays unencrypted at rest,
  so anyone who can read it can mint an RS256 id_token for any `sub`. `*.pem`
  sits in both `.gitignore` and `.dockerignore`, so neither a commit nor the
  Dockerfile's `COPY . /app` can pick up a locally generated key.
- A cert with **no `rfc822Name` SAN** cannot provision a downstream user, so
  federation fails fast and logs that reason. `identity.parse_client_identity`
  validates and lowercases emails, so the downstream value matches the one in
  the identity log line.
- OP access and refresh tokens are stateless signed blobs, so no server-side
  token table grows; a per-replica `jti` set keeps auth codes single-use within
  a replica, and the short code TTL bounds cross-replica replay.

## Running the integration stack

```bash
# Supply the mTLS CA PEM + TLS material (see docker-compose.vikunja.yml NOTE)
docker compose -f docker-compose.vikunja.yml up -d --build

RUN_INTEGRATION=1 TLS_CA=<server-ca.pem> \
  TLS_CLIENT_CERT=<client.crt> TLS_CLIENT_KEY=<client.key> \
  poetry run pytest tests/integration/test_integration_vikunja.py -v
```
