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
id/access token — that return call is omitted from the diagram for clarity.)

Envoy terminates the client mTLS certificate and forwards the verified cert PEM
(URL-encoded) in `attributes.source.certificate`. On each `Check`:

1. The cert is verified against the configured HA CA (+ CRL) and the
   `clientAuth` EKU is required.
2. On the **Frigate path** (`host == FRIGATE_HOST`) the existing behavior is
   preserved: inject `X-Proxy-Secret`. Federation does **not** run there.
3. If the request host is **claimed by a provider** (its `hosts` allowlist, see
   `providers.yaml`), the service derives a stable subject from the cert, then:
   - Vikunja's **own OIDC paths** (the frontend callback route and the backend
     endpoint that redeems a code) are let through **untouched** — see
     [Browser bootstrap](#browser-bootstrap-document-navigations) below.
   - A **document navigation** (a real browser address-bar/link hit, not an
     API/XHR call) gets the browser-bootstrap `denied_response` instead of the
     silent ladder — see below.
   - Everything else **federates**: it runs the `get_bearer` decision ladder,
     and either injects `Authorization: Bearer <token>` upstream, lets the
     client's own bearer through unchanged, or denies.
4. Any other allowed host passes through with **no header added**. Host scoping is
   an allowlist on purpose: attaching this ext_authz to a new vhost must not
   silently start injecting some other backend's bearer over the client's own
   credential.

## Browser bootstrap (document navigations)

`get_bearer`'s `Authorization` header is added to the request Envoy forwards
*upstream* — invisible to a browser's own JS. A browser SPA hitting Vikunja
directly therefore never becomes "logged in" from that alone: it still falls
through to Vikunja's own client-side OIDC login, which redirects to this
service's OP `authorization_endpoint` — a route that does not exist (see
`op/routes.py`: codes are minted server-to-server only, by design).

Reconciling this without any Envoy/Contour changes: `envoy_authz.federator.
browser_bootstrap` detects a top-level navigation (`Sec-Fetch-Dest: document`,
falling back to `Accept: text/html`) to a federated host and, instead of the
silent ladder, denies with an HTTP **200** whose body is a small page that
does exactly what Vikunja's own "Login with `<provider>`" button would have:
stores a `state` in `localStorage`, then navigates to Vikunja's callback route
with a code this service already minted (`store.create_authorization_code`,
the same call `federate()` uses). `DeniedHttpResponse.status`/`headers`/`body`
are fully caller-controlled — Envoy sends them straight to the browser without
ever proxying that hit to Vikunja — so this replicates Vikunja's real,
CSRF-checked front-channel flow (`OpenIdAuth.vue` hard-fails on a `state`
mismatch, so a bare server-side redirect that skipped setting it first would
not work).

Two paths must be exempted from this (and from the ladder) or the exchange
breaks: `frontend_oidc_path(provider)` (the callback page the bootstrap script
navigates to) and `vikunja.callback_path(provider)` (the API call that page
makes to redeem the code) are always let through untouched.

There is no way to tell from the server side whether a browser already holds
a valid Vikunja JWT, so this runs on **every** document navigation to a
federated host, not just the first. That is intentional, not a cache miss:
this whole model derives a session from the mTLS cert per request, so a full
page reload legitimately re-deriving a fresh one is consistent with treating
"logout" as meaningless while the cert is presented.

## Native app OAuth (authorization-code + PKCE)

The browser bootstrap logs Vikunja's *web frontend* in. The native app
(`vikunja-flutter`) instead runs a standard OAuth **authorization-code + PKCE**
login against the public URL, and must never see the downstream OIDC handshake
— only its own code and tokens. `envoy_authz.federator.app_oauth` synthesizes
both legs entirely from the mTLS identity (`grpc_service.Check` answers each
with a `denied_response`, so neither hit reaches Vikunja):

- **`GET /oauth/authorize`** (matched by `client_id=vikunja-flutter`, checked
  *before* the browser-bootstrap branch since it is itself a document
  navigation): validates `response_type=code`, the `redirect_uri` allowlist and
  an S256 `code_challenge`, mints a **subject-bound** PKCE code
  (`store.create_authorization_code`, `user_id=subject.sub`), and denies with a
  **302** straight to `vikunja-flutter://callback?code=…&state=…`. The browser
  follows the custom-scheme redirect back into the app; no Vikunja page renders.
- **`POST …/oauth/token`** (matched by `client_id` in the body): reads the body
  (see the `with_request_body` requirement below), verifies the code
  (signature, TTL, single use), the `redirect_uri`, PKCE, and that the **same
  certificate subject** redeems it, then federates server-side
  (`vikunja.federate`) and returns the Vikunja bearer as
  `{access_token, token_type, expires_in, refresh_token}`. `grant_type=
  refresh_token` (also subject-bound) re-federates for a fresh bearer. The app
  posts this body as **JSON** (`Content-Type: application/json`), not the RFC
  6749 form encoding, so the body parser honours the Content-Type and accepts
  either.

Security note: the whole exchange is over mutually-authenticated TLS, so the
real principal on both legs is the client certificate. Binding the code and
refresh token to `subject.sub` — refusing them to any other certificate — is
what makes this safe for this transport; PKCE is verified additionally.

> **Deployment requirement:** the token/refresh bodies arrive in the POST body,
> which an ext_authz filter only forwards to `Check` when configured with
> [`with_request_body`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto)
> (`max_request_bytes` ≥ a few KiB, `pack_as_bytes: false`). Without it the
> body is empty, the token leg is simply not matched, and the request falls
> through to Vikunja (which 404s it). Set this on the edge Envoy/Contour
> ext_authz filter in every environment that serves the native app.

## The `get_bearer` decision ladder

Per request, for a derived `Subject` (`sub` is a 16-char SHA-256 of the cert's
subject DN DER + SubjectPublicKeyInfo DER):

1. **Incoming bearer present?** If a `session_secret` is configured, verify the
   bearer's HS256 signature + `exp` locally **and** check that it is a Vikunja
   *user* token (`type`) belonging to the Vikunja user this mTLS subject already
   maps to. Valid, bound and not near-expiry → **allow through unchanged**
   (return `None`, no `Authorization` header added). Otherwise → fall to step 2.

   The binding matters: Vikunja signs link-share tokens with the same
   `service.secret` and hands them out to anyone with a public share hash, so a
   valid signature alone does not identify a user. Without the `id`/`type` check
   a cert holder could present *another* user's bearer and be served as them,
   making the mTLS identity irrelevant on this branch.
2. **Cached session?** A per-identity in-memory cache keyed by `sub`. A fresh
   cached entry → inject its bearer. A stale entry with a refresh cookie →
   step 3. A stale entry without a refresh cookie, or no cache → step 4.
3. **Refresh** (`POST /api/v1/user/token/refresh` with the refresh cookie):
   `200` → rotate, cache, inject. `401` (revoked) or any other **terminal**
   failure → drop the cache entry and fall through to step 4, so a permanently
   dead cookie is not retried forever. Transport error / `5xx` → deny (503),
   keeping the entry (its cookie is probably still good).
4. **Federate** (mint an OP auth code, `POST {code, redirect_url}` to Vikunja's
   OpenID callback): `200` → cache, inject. Failure → deny.

Steps 3 and 4 both run under a **per-identity lock**, so concurrent requests for
one user neither double-federate nor race on Vikunja's single-use refresh cookie.
Locks are striped (fixed-size array), and the session cache is bounded by expiry
plus a max-entry cap.

**The hot path never calls Vikunja** — validity is decided locally via `exp` and
the cache; only the cold paths (refresh/federate) reach Vikunja. There is no
per-request `GET /api/v1/user`.

## Return contract

This ladder only runs for non-navigation requests (see
[Browser bootstrap](#browser-bootstrap-document-navigations) above for how a
real browser page load is handled instead):

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
The OP is a FastAPI router mounted at the app root and initialized at startup
(the RSA signing key is loaded-or-created from `OP_KEY_PATH`); discovery
advertises `IDP_ISSUER` as the issuer:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery (issuer, endpoints, `RS256`, PKCE `S256`/`plain`) |
| `GET /jwks.json` | Public signing key (`kid`, RS256) |
| `POST /oauth/token` | Auth-code → `{access_token, id_token, refresh_token}`; refresh rotation |
| `GET/POST /oauth/userinfo` | Scoped `sub`/`name`/`email` for a bearer |

Auth codes are **stateless** (`itsdangerous` signed, short TTL): `email`/`name`
travel inside the signed payload, so the OP has no `USERS` store —
`authenticate_user` reconstructs the user from the code/token record. Codes are
**single-use**: each carries a `jti` that is recorded on redemption (RFC 6749
§4.1.2), so an observed code cannot be replayed within its TTL.

## `providers.yaml`

Each entry is one downstream backend the federator can federate to. Values may
reference the environment as `${VAR}` or `${VAR:-default}` (an undefined
`${VAR}` with no default is a fatal startup error).

A variable that is **unset or empty** falls back to its default (an empty k8s
secret value is a missing secret, not a deliberate empty one); with no default,
unset-or-empty is a fatal startup error. Use `${VAR:-}` to opt into empty.
Secrets deliberately have **no default** — a missing injection must fail startup
rather than silently fall back to a value published in this repo.

`hosts` is the allowlist of Envoy request hosts this backend federates for.

```yaml
providers:
  vikunja:
    hosts:
      - "${VIKUNJA_HOST:-vikunja.apps.somemissing.info}"
    client_id: "${VIKUNJA_CLIENT_ID:-vikunja}"
    client_secret: "${VIKUNJA_CLIENT_SECRET}"   # no default: must be injected
    redirect_url: "${VIKUNJA_REDIRECT_URL:-http://localhost:3456/auth/openid/broker}"
    api_base: "${VIKUNJA_API_BASE:-http://localhost:3456}"
    provider_key: "${VIKUNJA_PROVIDER_KEY:-broker}"
    scope: "openid profile email"
    extra:
      # Vikunja service.secret (HS256). When set, the federator verifies an
      # incoming bearer's signature + exp locally before trusting it. When
      # unset, incoming bearers are treated as opaque (cache is used).
      session_secret: "${VIKUNJA_SESSION_SECRET:-}"
```

The callback URL is `{api_base}/api/v1/auth/openid/{provider_key}/callback`,
built by `vikunja.federate` (the wire contract lives with the client).

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

**Federation is opt-in.** It is enabled only when all three of `IDP_ISSUER`,
`SECRET_KEY` and `PROVIDERS_FILE` are set. With any of them missing the service
logs `Federation disabled …`, mounts no OP, wires no federator, and behaves
exactly as it did before this layer existed — the mTLS allow gate plus the
Frigate `X-Proxy-Secret`. That is what keeps the existing k8s manifest (which
sets only `FRIGATE_X_PROXY_SECRET` and `HA_CA_CERTIFICATE`) valid: it continues
to deploy and run unchanged, with federation off until those vars are added.

There is no usable default for `PROVIDERS_FILE`: the shipped file lives at
`envoy_authz/providers.yaml` inside the package, which does not match the
container's working directory, so the path must be given explicitly (the compose
stack mounts it at `/etc/envoy-authz/providers.yaml`).

## Security notes

- **Bearer tokens and refresh cookies are never logged.** Log lines carry only
  the subject `sub` and the decision branch.
- **No bearer signature check on tokens we obtain ourselves** — we trust the
  token received over our trusted channel to Vikunja and read only `exp`/`id`.
  An *incoming client* bearer is only trusted when `session_secret` is set and
  its HS256 signature + `exp` verify locally.
- Refresh-token cookies are extracted verbatim from `Set-Cookie`, including the
  comma-bearing `Expires` case.
- Per-identity locking prevents concurrent same-user double-federation **and**
  refresh-cookie races; sessions are cached server-side (bounded) and injected
  upstream via ext_authz `headers`.
- **The OP signing key is written `0600`** in a `0700` directory, and an existing
  key with looser bits is tightened on load. It is unencrypted at rest, so anyone
  who can read it can mint an RS256 id_token for any `sub`. `*.pem` is in both
  `.gitignore` and `.dockerignore` so a locally generated key cannot be committed
  or baked into an image by the Dockerfile's `COPY . /app`.
- A cert with **no `rfc822Name` SAN** cannot provision a downstream user, so
  federation fails fast with that reason logged. Emails are validated and
  lowercased by `identity.parse_client_identity`, so the value sent downstream
  matches the one in the identity log line.
- Auth codes are single-use; the OP's in-memory token records are pruned on
  expiry rather than growing for the process lifetime.

## Running the integration stack

```bash
# Supply the mTLS CA PEM + TLS material (see docker-compose.vikunja.yml NOTE)
docker compose -f docker-compose.vikunja.yml up -d --build

RUN_INTEGRATION=1 TLS_CA=<server-ca.pem> \
  TLS_CLIENT_CERT=<client.crt> TLS_CLIENT_KEY=<client.key> \
  poetry run pytest tests/integration/test_integration_vikunja.py -v
```
