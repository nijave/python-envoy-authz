# Client Certificate Identity Extraction — Design

Date: 2026-07-21

## Summary

Add a Pydantic model that best-effort parses identity and key-policy
attributes out of a verified X.509 client certificate, and emit the parsed
identity in the existing structured log line on each authorized `Check` call.
Every field is optional, mirroring that each attribute is optional on the
certificate itself. This is a log-only feature: it does not change allow/deny
behavior and does not add response headers.

## Goals

- Extract subject-DN identity attributes, SAN email addresses, and the
  BasicConstraints / KeyUsage / ExtendedKeyUsage extensions from a client cert.
- Validate each field as strictly as the relevant RFCs allow, but degrade
  gracefully: a single malformed attribute must not lose the whole identity.
- Log the identity for verified/trusted certificates only.

## Non-goals

- No forwarding of identity as request/response headers to upstreams.
- No change to the authorization (allow/deny) decision.
- No parsing of identity from unverified/untrusted certificates.

## Placement

New module `envoy_authz/identity.py` containing:

- `ClientIdentity` — a flat Pydantic v2 model; every field optional/defaulted.
- `parse_client_identity(cert: x509.Certificate) -> ClientIdentity` — a
  best-effort extractor.

`envoy_authz/app.py` changes:

- `verify_client_cert(cert_pem, store)` is refactored to return the verified
  `cryptography.x509.Certificate | None` (the verified leaf certificate on
  success, `None` on any failure) instead of `bool`. Truthiness is preserved
  for the existing `allowed` expression.
- In `Check`, when the request is authorized *because* a client cert verified,
  call `parse_client_identity(cert)` and include
  `identity=model.model_dump(exclude_none=True)` in the existing "Authorized"
  structured log line's `extra`. The Frigate `/api/metrics` no-cert path adds
  no identity.

## Model fields and validation

All fields optional or defaulted. Bounds are taken from RFC 5280, ITU-T X.520
(`ub-*` upper bounds), and RFC 5321 (email). Strings are whitespace-stripped
and rejected when empty after stripping.

| Field | Source | Type | Validation |
|---|---|---|---|
| `common_name` | DN OID 2.5.4.3 | `str \| None` | 1–64 chars (`ub-common-name`) |
| `surname` | DN OID 2.5.4.4 | `str \| None` | 1–32768 (`ub-name`) |
| `given_name` | DN OID 2.5.4.42 | `str \| None` | 1–32768 (`ub-name`) |
| `display_name` | DN OID 2.16.840.1.113730.3.1.241 | `str \| None` | 1–256 (no RFC max; sanity cap) |
| `organization` | DN OID 2.5.4.10 | `str \| None` | 1–64 (`ub-organization-name`); first value if repeated |
| `organizational_units` | DN OID 2.5.4.11 | `list[str]` | each 1–64 (`ub-organizational-unit-name`); multi-valued |
| `uid` | DN OID 0.9.2342.19200300.100.1.1 | `str \| None` | 1–256 (no RFC max; sanity cap) |
| `primary_email` | SAN rfc822Name[0] | `str \| None` | ASCII; exactly one `@`; local ≤64; domain ≤255; total ≤254; lowercased |
| `additional_email_addresses` | SAN rfc822Name[1:] | `list[str]` | same email rule, per element |
| `is_ca` | BasicConstraints | `bool \| None` | — |
| `path_length` | BasicConstraints | `int \| None` | ≥ 0 |
| `key_usages` | KeyUsage extension | `list[str]` | names of asserted usages, e.g. `digital_signature`, `key_encipherment` |
| `extended_key_usages` | ExtendedKeyUsage extension | `list[str]` | friendly name (e.g. `clientAuth`) when known, else dotted OID |

### OID note (research finding)

The requested `displayName` OID `2.5.4.53` is **not** displayName — per the
X.500 registry it is `deltaRevocationList` (RFC 4523), a CRL-holding attribute.
`dnQualifier` is `2.5.4.46`. The real `displayName` is
`2.16.840.1.113730.3.1.241` (inetOrgPerson, RFC 2798), an unbounded Directory
String. The model reads `display_name` from the correct OID
`2.16.840.1.113730.3.1.241`.

### Email validation

A custom validator is used rather than `pydantic.EmailStr`, to avoid adding the
`email-validator` dependency and because `rfc822Name` requires an ASCII
`IA5String` bare mailbox (`Local-part@Domain`, no display phrase, comment, or
angle brackets) with the RFC 5321 length limits (local-part ≤ 64 octets, domain
≤ 255 octets, whole address ≤ 254 octets). Addresses are lowercased for
consistent comparison.

## Best-effort mechanics

`parse_client_identity` pulls raw candidate values out of the certificate
(subject RDNs by OID, SAN `rfc822Name` entries in order, and the three
extensions), then validates each field independently against its own constraint
(via per-field `TypeAdapter`s derived from the model's field annotations, so the
model remains the single source of truth for the constraints):

- Invalid scalar values are dropped to `None`.
- Invalid elements of a list field are filtered out; valid siblings are kept.
- Each dropped value logs a warning (attribute name + reason), without the
  attribute value where it could be sensitive/oversized.

`ClientIdentity()` with no valid fields is a legal, all-empty model.
Extensions that are absent leave their fields at `None` / `[]`.

## Dependencies

- Add `pydantic (>=2,<3)` to the project's runtime dependencies.
- Promote `cryptography` from the dev dependency group into runtime
  dependencies. It is already imported at runtime in `app.py`
  (`cert.to_cryptography()`), currently satisfied only transitively via
  pyOpenSSL; parsing makes this a first-class runtime dependency.

## Testing

Extend `tests/conftest.py` with certificate builders that carry the full
attribute set (all DN identity fields, the displayName extension OID, uid,
multiple SAN emails, key usage / EKU / basic constraints), plus targeted
edge-case builders.

Unit tests (`tests/` — a new `tests/unit/` or module-level file for the parser):

- Certificate with every field populated → every field parsed correctly.
- Bare certificate (only CN) → all other fields `None`/empty.
- Multi-valued OU → `organizational_units` list preserves all values.
- Multiple SAN emails → `primary_email` is the first, remainder in
  `additional_email_addresses`.
- Invalid SAN email present alongside valid ones → invalid dropped, valid kept.
- Over-length common name → `common_name` dropped, other fields kept.
- `display_name` read from the correct OID `2.16.840.1.113730.3.1.241`.
- `uid` parsed from OID `0.9.2342.19200300.100.1.1`.
- KeyUsage / ExtendedKeyUsage / BasicConstraints extracted (including CA:FALSE,
  clientAuth EKU, expected key-usage flags).

Integration test:

- A trusted client cert produces a `Check` "Authorized" log line whose `extra`
  contains the parsed `identity` (asserted via log capture).

## Rollout / risk

- Log-only; no behavior change to authorization decisions.
- Parsing runs only after successful CA + CRL + EKU verification, so DN values
  logged are from certs the trusted CA issued.
- Failure inside `parse_client_identity` must never affect the authorization
  decision: parsing is wrapped so any unexpected error is logged and the
  request still returns its already-decided response.
