---
name: project-frigate-proxy-secret
description: Why python-envoy-authz injects X-Proxy-Secret on the unauthenticated Frigate /api/metrics path
metadata: 
  node_type: memory
  type: project
  originSessionId: be8b7d23-c029-4892-a2b4-08dc08b914ab
---

`envoy_authz/app.py` injects `X-Proxy-Secret` on every allowed Frigate request, including the unauthenticated `/api/metrics` exemption. This is intentional, not a bug: Frigate's metrics endpoint requires the `X-Proxy-Secret` header to be present, so the auth service must inject it on the metrics path even when no client cert was used to authorize the request.

**Why:** Frigate uses `X-Proxy-Secret` as the marker that a request is coming from a trusted upstream proxy. The metrics endpoint enforces that check on the Frigate side, so the auth service has to provide the secret regardless of whether the inbound request was cert-authed or fell under the no-auth metrics exemption.

**How to apply:** Tests for the Frigate metrics path should expect `X-Proxy-Secret` to equal the configured secret value, not to be absent. Do not refactor `app.py` to gate the secret on cert-authed allow paths only — that would break metrics scraping.
