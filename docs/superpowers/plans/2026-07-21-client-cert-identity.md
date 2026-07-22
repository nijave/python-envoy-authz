# Client Certificate Identity Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Best-effort parse identity + key-policy attributes out of a verified X.509 client certificate into a validated Pydantic model, and log them on each authorized `Check`.

**Architecture:** A new `envoy_authz/identity.py` module defines a flat Pydantic v2 `ClientIdentity` model (every field optional) and a `parse_client_identity(cert)` extractor that validates each field independently, dropping (and logging) any that fail so a single bad attribute never loses the rest. `app.py`'s `verify_client_cert` is refactored to return the verified `cryptography.x509.Certificate | None`; on an authorized cert request, the parsed identity is added to the existing structured log line. Log-only: no change to allow/deny, no response headers.

**Tech Stack:** Python 3.12+, Pydantic v2, `cryptography` (x509), pyOpenSSL, pytest, Poetry.

## Global Constraints

- Python `>=3.12` (`requires-python`).
- Every `ClientIdentity` field is optional/defaulted — parsing never raises on missing or malformed attributes.
- Parsing runs only for certs that already passed CA + CRL + `clientAuth` EKU verification.
- Parsing failure must never change the authorization decision.
- `displayName` reads from OID `2.16.840.1.113730.3.1.241` (NOT `2.5.4.53`).
- Email validation: ASCII only, exactly one `@`, local-part ≤ 64 octets, domain ≤ 255 octets, whole address ≤ 254 octets, no angle brackets; lowercased.
- Ruff line length is the default 88; run `ruff` + `ruff-format` (via pre-commit) clean before each commit.
- Run tests with `.venv/bin/python -m pytest`. Manage deps with `~/.pyenv/versions/3.12.3/bin/poetry` (targets the in-project `.venv`).
- Stage explicit paths in each commit; never blanket `git add`.

---

### Task 1: Add pydantic + promote cryptography to runtime dependencies

**Files:**
- Modify: `pyproject.toml` (dependencies + dev group)

**Interfaces:**
- Consumes: nothing.
- Produces: `pydantic` importable at runtime; `cryptography` a first-class runtime dependency.

- [ ] **Step 1: Add pydantic and cryptography to runtime dependencies**

In `pyproject.toml`, change the `[project].dependencies` list to add the two entries (keep existing entries):

```toml
dependencies = [
    "grpcio (>=1.76.0,<2.0.0)",
    "grpcio-tools (>=1.76.0,<2.0.0)",
    "envoyproxy-envoy-grpc-python (==1.76.0.1.20251020202141+86528c2a7812)",
    "pyopenssl (>=25.3.0,<26.0.0)",
    "python-json-logger (>=4.0.0,<5.0.0)",
    "grpcio-health-checking (>=1.80.0,<2.0.0)",
    "pydantic (>=2.0.0,<3.0.0)",
    "cryptography (>=44.0.0,<46.0.0)"
]
```

- [ ] **Step 2: Remove cryptography from the dev dependency group**

In `pyproject.toml`, edit `[dependency-groups].dev` to drop the `cryptography` line (it moved to runtime):

```toml
dev = [
    "ruff (>=0.14.5,<0.15.0)",
    "pytest (>=8.3.0,<9.0.0)",
    "pre-commit (>=4.6.0,<5.0.0)"
]
```

- [ ] **Step 3: Lock and install**

Run: `~/.pyenv/versions/3.12.3/bin/poetry lock && ~/.pyenv/versions/3.12.3/bin/poetry install`
Expected: resolves and installs; `poetry.lock` updated to include `pydantic` (and `pydantic-core`).

- [ ] **Step 4: Verify pydantic imports in the venv**

Run: `.venv/bin/python -c "import pydantic; print(pydantic.VERSION)"`
Expected: prints a `2.x` version, no traceback.

- [ ] **Step 5: Verify existing tests still pass**

Run: `.venv/bin/python -m pytest -q`
Expected: all existing tests PASS.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml poetry.lock
git commit -m "build: add pydantic, promote cryptography to runtime deps"
```

---

### Task 2: ClientIdentity model + email validator

**Files:**
- Create: `envoy_authz/identity.py`
- Create: `tests/unit/__init__.py` (empty)
- Test: `tests/unit/test_identity_model.py`

**Interfaces:**
- Consumes: nothing (pure model).
- Produces:
  - `ClientIdentity` — Pydantic `BaseModel` with fields: `common_name: str | None`, `surname: str | None`, `given_name: str | None`, `display_name: str | None`, `organization: str | None`, `organizational_units: list[str]`, `uid: str | None`, `primary_email: str | None`, `additional_email_addresses: list[str]`, `is_ca: bool | None`, `path_length: int | None`, `key_usages: list[str]`, `extended_key_usages: list[str]`.
  - Annotated constraint aliases: `CommonName`, `Name`, `DisplayName`, `OrgName`, `Uid`, `Email` (used by Task 3).
  - `_validate_email(value: str) -> str` — raises `ValueError` on invalid; returns lowercased address.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/__init__.py` (empty file), then `tests/unit/test_identity_model.py`:

```python
"""Unit tests for the ClientIdentity Pydantic model and email validation."""

import pytest
from pydantic import ValidationError

from envoy_authz.identity import ClientIdentity, _validate_email


def test_empty_model_is_all_optional():
    identity = ClientIdentity()
    assert identity.common_name is None
    assert identity.organizational_units == []
    assert identity.additional_email_addresses == []
    assert identity.key_usages == []
    assert identity.is_ca is None


def test_valid_fields_accepted_and_stripped():
    identity = ClientIdentity(
        common_name="  Jane Doe  ",
        organization="ACME",
        organizational_units=["eng", "sre"],
        uid="jdoe",
    )
    assert identity.common_name == "Jane Doe"
    assert identity.organization == "ACME"
    assert identity.organizational_units == ["eng", "sre"]
    assert identity.uid == "jdoe"


def test_common_name_over_64_rejected():
    with pytest.raises(ValidationError):
        ClientIdentity(common_name="x" * 65)


def test_empty_string_common_name_rejected():
    with pytest.raises(ValidationError):
        ClientIdentity(common_name="   ")


def test_path_length_negative_rejected():
    with pytest.raises(ValidationError):
        ClientIdentity(path_length=-1)


@pytest.mark.parametrize(
    "address,expected",
    [
        ("Jane@Example.COM", "jane@example.com"),
        ("  jdoe@example.com  ", "jdoe@example.com"),
    ],
)
def test_validate_email_normalizes(address, expected):
    assert _validate_email(address) == expected


@pytest.mark.parametrize(
    "address",
    [
        "",
        "no-at-sign",
        "two@@example.com",
        "a@b@example.com",
        "<jdoe@example.com>",
        "jdoé@example.com",  # non-ASCII
        ("x" * 65) + "@example.com",  # local-part > 64
        "jdoe@" + ("d" * 256) + ".com",  # domain > 255
    ],
)
def test_validate_email_rejects_invalid(address):
    with pytest.raises(ValueError):
        _validate_email(address)


def test_model_rejects_invalid_email():
    with pytest.raises(ValidationError):
        ClientIdentity(primary_email="not-an-email")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_identity_model.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'envoy_authz.identity'`.

- [ ] **Step 3: Write the model and validator**

Create `envoy_authz/identity.py`:

```python
"""Best-effort extraction of identity attributes from a verified X.509 client
certificate into a validated Pydantic model.

Every field is optional: X.509 subject attributes and SAN entries are all
optional, so a certificate may carry any subset. The `parse_client_identity`
extractor validates each field independently and drops (logging) any value that
fails validation, so a single malformed attribute never loses the rest of the
identity.
"""

import logging
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, StringConstraints

logger = logging.getLogger(__name__)

# RFC 5321 mailbox octet limits for rfc822Name SAN values.
_MAX_EMAIL_LOCAL = 64
_MAX_EMAIL_DOMAIN = 255
_MAX_EMAIL_TOTAL = 254


def _validate_email(value: str) -> str:
    """Validate an rfc822Name-style bare mailbox and return it lowercased.

    Enforces ASCII (IA5String), exactly one '@', non-empty local-part/domain,
    no angle brackets, and the RFC 5321 length limits. Raises ValueError on any
    violation so callers can treat it as a dropped field.
    """
    address = value.strip()
    if not address:
        raise ValueError("email is empty")
    try:
        address.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("email must be ASCII (IA5String)") from exc
    if address.count("@") != 1:
        raise ValueError("email must contain exactly one '@'")
    if "<" in address or ">" in address:
        raise ValueError("email must not contain angle brackets")
    local, domain = address.split("@")
    if not local or not domain:
        raise ValueError("email local-part and domain must be non-empty")
    if len(local.encode()) > _MAX_EMAIL_LOCAL:
        raise ValueError("email local-part exceeds 64 octets")
    if len(domain.encode()) > _MAX_EMAIL_DOMAIN:
        raise ValueError("email domain exceeds 255 octets")
    if len(address.encode()) > _MAX_EMAIL_TOTAL:
        raise ValueError("email exceeds 254 octets")
    return address.lower()


# Shared constraint aliases — the single source of truth for per-field bounds,
# reused by both the model below and the per-field TypeAdapters in Task 3.
CommonName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)
]
Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32768)
]
DisplayName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
OrgName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)
]
Uid = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
Email = Annotated[str, StringConstraints(strip_whitespace=True), AfterValidator(_validate_email)]


class ClientIdentity(BaseModel):
    """Identity and key-policy attributes extracted from a client certificate.

    Every field is optional; absent attributes stay None / empty list.
    """

    common_name: CommonName | None = None
    surname: Name | None = None
    given_name: Name | None = None
    display_name: DisplayName | None = None
    organization: OrgName | None = None
    organizational_units: list[OrgName] = Field(default_factory=list)
    uid: Uid | None = None
    primary_email: Email | None = None
    additional_email_addresses: list[Email] = Field(default_factory=list)
    is_ca: bool | None = None
    path_length: Annotated[int, Field(ge=0)] | None = None
    key_usages: list[str] = Field(default_factory=list)
    extended_key_usages: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_identity_model.py -q`
Expected: all PASS.

- [ ] **Step 5: Lint/format**

Run: `.venv/bin/python -m pre_commit run --files envoy_authz/identity.py tests/unit/test_identity_model.py tests/unit/__init__.py`
Expected: ruff + ruff-format pass (auto-fix formatting if needed, then re-run until clean).

- [ ] **Step 6: Commit**

```bash
git add envoy_authz/identity.py tests/unit/__init__.py tests/unit/test_identity_model.py
git commit -m "feat: add ClientIdentity model and email validation"
```

---

### Task 3: parse_client_identity extractor

**Files:**
- Modify: `envoy_authz/identity.py`
- Test: `tests/unit/test_identity_parse.py`

**Interfaces:**
- Consumes: `ClientIdentity`, `CommonName`, `Name`, `DisplayName`, `OrgName`, `Uid`, `Email` from Task 2; `cryptography.x509`.
- Produces: `parse_client_identity(cert: cryptography.x509.Certificate) -> ClientIdentity`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_identity_parse.py`:

```python
"""Unit tests for parse_client_identity against built certificates."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from envoy_authz.identity import parse_client_identity

_DISPLAY_NAME_OID = ObjectIdentifier("2.16.840.1.113730.3.1.241")


def _build_cert(
    *,
    name_attrs: list[x509.NameAttribute],
    san_emails: list[str] | None = None,
    eku: list[ObjectIdentifier] | None = None,
    ca: bool = False,
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name(name_attrs)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(eku or [ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )
    if san_emails:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(e) for e in san_emails]),
            critical=False,
        )
    return builder.sign(private_key=key, algorithm=hashes.SHA256())


def test_full_identity_parsed():
    cert = _build_cert(
        name_attrs=[
            x509.NameAttribute(NameOID.COMMON_NAME, "Jane Doe"),
            x509.NameAttribute(NameOID.SURNAME, "Doe"),
            x509.NameAttribute(NameOID.GIVEN_NAME, "Jane"),
            x509.NameAttribute(_DISPLAY_NAME_OID, "Jane D."),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "eng"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sre"),
            x509.NameAttribute(NameOID.USER_ID, "jdoe"),
        ],
        san_emails=["jane@example.com", "jane.doe@example.org"],
    )
    identity = parse_client_identity(cert)
    assert identity.common_name == "Jane Doe"
    assert identity.surname == "Doe"
    assert identity.given_name == "Jane"
    assert identity.display_name == "Jane D."
    assert identity.organization == "ACME"
    assert identity.organizational_units == ["eng", "sre"]
    assert identity.uid == "jdoe"
    assert identity.primary_email == "jane@example.com"
    assert identity.additional_email_addresses == ["jane.doe@example.org"]
    assert identity.is_ca is False
    assert "digital_signature" in identity.key_usages
    assert "key_encipherment" in identity.key_usages
    assert identity.extended_key_usages == ["clientAuth"]


def test_bare_cert_only_common_name():
    cert = _build_cert(
        name_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "bare")],
    )
    identity = parse_client_identity(cert)
    assert identity.common_name == "bare"
    assert identity.surname is None
    assert identity.organization is None
    assert identity.organizational_units == []
    assert identity.primary_email is None
    assert identity.additional_email_addresses == []


def test_display_name_read_from_correct_oid_not_2_5_4_53():
    # 2.5.4.53 is deltaRevocationList, NOT displayName; it must be ignored.
    cert = _build_cert(
        name_attrs=[
            x509.NameAttribute(NameOID.COMMON_NAME, "cn"),
            x509.NameAttribute(ObjectIdentifier("2.5.4.53"), "wrong-oid-value"),
        ],
    )
    identity = parse_client_identity(cert)
    assert identity.display_name is None


def test_invalid_email_dropped_valid_kept():
    cert = _build_cert(
        name_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "cn")],
        san_emails=["not-an-email", "good@example.com"],
    )
    identity = parse_client_identity(cert)
    # primary is positional [0] and invalid -> dropped; [1:] valid kept.
    assert identity.primary_email is None
    assert identity.additional_email_addresses == ["good@example.com"]


def test_over_length_common_name_dropped_others_kept():
    cert = _build_cert(
        name_attrs=[
            x509.NameAttribute(NameOID.COMMON_NAME, "x" * 65),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME"),
        ],
    )
    identity = parse_client_identity(cert)
    assert identity.common_name is None
    assert identity.organization == "ACME"


def test_extended_key_usage_unknown_oid_falls_back_to_dotted():
    cert = _build_cert(
        name_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "cn")],
        eku=[ObjectIdentifier("1.3.6.1.4.1.99999.1")],
    )
    identity = parse_client_identity(cert)
    assert identity.extended_key_usages == ["1.3.6.1.4.1.99999.1"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/test_identity_parse.py -q`
Expected: FAIL with `ImportError: cannot import name 'parse_client_identity'`.

- [ ] **Step 3: Implement the extractor**

Append to `envoy_authz/identity.py`. First add these imports to the existing import block at the top of the file:

```python
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
)
```

(Replace the earlier `from pydantic import AfterValidator, BaseModel, Field, StringConstraints` line with the expanded one above, and add the two `cryptography` imports.)

Then append to the end of the file:

```python
# Subject DN attribute OIDs. displayName uses the inetOrgPerson OID
# (RFC 2798); 2.5.4.53 is deltaRevocationList and is intentionally not read.
_OID_DISPLAY_NAME = ObjectIdentifier("2.16.840.1.113730.3.1.241")

# Friendly names for the EKU OIDs cryptography exposes as constants; unknown
# OIDs fall back to their dotted string.
_EKU_NAMES: dict[ObjectIdentifier, str] = {
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning",
    ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE: "anyExtendedKeyUsage",
    ExtendedKeyUsageOID.SMARTCARD_LOGON: "smartcardLogon",
    ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC: "pkInitKDC",
}

# KeyUsage flags always safe to read.
_KEY_USAGE_FLAGS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
)

# Per-field validators, keyed by ClientIdentity field name, reusing the shared
# constraint aliases so the model stays the single source of truth.
_SCALAR_ADAPTERS: dict[str, TypeAdapter] = {
    "common_name": TypeAdapter(CommonName),
    "surname": TypeAdapter(Name),
    "given_name": TypeAdapter(Name),
    "display_name": TypeAdapter(DisplayName),
    "organization": TypeAdapter(OrgName),
    "uid": TypeAdapter(Uid),
}
_ORG_UNIT_ADAPTER: TypeAdapter = TypeAdapter(OrgName)
_EMAIL_ADAPTER: TypeAdapter = TypeAdapter(Email)


def _first_attr(name: x509.Name, oid: ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    for attr in attrs:
        if isinstance(attr.value, str):
            return attr.value
    return None


def _all_str_attrs(name: x509.Name, oid: ObjectIdentifier) -> list[str]:
    return [a.value for a in name.get_attributes_for_oid(oid) if isinstance(a.value, str)]


def _san_emails(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(san.value.get_values_for_type(x509.RFC822Name))


def _key_usages(cert: x509.Certificate) -> list[str]:
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return []
    names = [flag for flag in _KEY_USAGE_FLAGS if getattr(usage, flag)]
    # encipher_only / decipher_only are only defined when key_agreement is set;
    # accessing them otherwise raises ValueError.
    if usage.key_agreement:
        for flag in ("encipher_only", "decipher_only"):
            if getattr(usage, flag):
                names.append(flag)
    return names


def _extended_key_usages(cert: x509.Certificate) -> list[str]:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return []
    return [_EKU_NAMES.get(oid, oid.dotted_string) for oid in eku]


def _basic_constraints(cert: x509.Certificate) -> tuple[bool | None, int | None]:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None, None
    return bc.ca, bc.path_length


def _validate_scalar(field: str, adapter: TypeAdapter, value: str) -> str | None:
    try:
        return adapter.validate_python(value)
    except ValidationError as exc:
        logger.warning(
            "Dropping invalid client-cert field %s: %s",
            field,
            exc.errors()[0]["msg"],
        )
        return None


def _validate_list(field: str, adapter: TypeAdapter, values: list[str]) -> list[str]:
    validated: list[str] = []
    for value in values:
        result = _validate_scalar(field, adapter, value)
        if result is not None:
            validated.append(result)
    return validated


def parse_client_identity(cert: x509.Certificate) -> ClientIdentity:
    """Best-effort extraction of identity attributes from a verified cert.

    Each field is validated independently; values that fail validation are
    dropped (and logged), so a single malformed attribute never loses the rest.
    """
    subject = cert.subject
    is_ca, path_length = _basic_constraints(cert)
    emails = _san_emails(cert)

    raw_scalars = {
        "common_name": _first_attr(subject, NameOID.COMMON_NAME),
        "surname": _first_attr(subject, NameOID.SURNAME),
        "given_name": _first_attr(subject, NameOID.GIVEN_NAME),
        "display_name": _first_attr(subject, _OID_DISPLAY_NAME),
        "organization": _first_attr(subject, NameOID.ORGANIZATION_NAME),
        "uid": _first_attr(subject, NameOID.USER_ID),
    }

    kwargs: dict = {
        "is_ca": is_ca,
        "path_length": path_length,
        "organizational_units": _validate_list(
            "organizational_units",
            _ORG_UNIT_ADAPTER,
            _all_str_attrs(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        ),
        "key_usages": _key_usages(cert),
        "extended_key_usages": _extended_key_usages(cert),
    }

    for field, adapter in _SCALAR_ADAPTERS.items():
        value = raw_scalars[field]
        if value is None:
            continue
        validated = _validate_scalar(field, adapter, value)
        if validated is not None:
            kwargs[field] = validated

    if emails:
        primary = _validate_scalar("primary_email", _EMAIL_ADAPTER, emails[0])
        if primary is not None:
            kwargs["primary_email"] = primary
        kwargs["additional_email_addresses"] = _validate_list(
            "additional_email_addresses", _EMAIL_ADAPTER, emails[1:]
        )

    return ClientIdentity(**kwargs)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_identity_parse.py -q`
Expected: all PASS.

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all PASS.

- [ ] **Step 6: Lint/format**

Run: `.venv/bin/python -m pre_commit run --files envoy_authz/identity.py tests/unit/test_identity_parse.py`
Expected: ruff + ruff-format pass.

- [ ] **Step 7: Commit**

```bash
git add envoy_authz/identity.py tests/unit/test_identity_parse.py
git commit -m "feat: add parse_client_identity best-effort extractor"
```

---

### Task 4: Wire identity into app.py Check and log it

**Files:**
- Modify: `envoy_authz/app.py` (imports, `verify_client_cert`, `Check`)
- Test: `tests/integration/test_check.py` (add one log-capture test)

**Interfaces:**
- Consumes: `parse_client_identity` from Task 3.
- Produces: `verify_client_cert(cert_pem, store) -> x509.Certificate | None`; authorized cert requests log `identity` in the "✓ Authorized" line's `extra`.

- [ ] **Step 1: Write the failing test**

Add to `tests/integration/test_check.py`:

```python
def test_authorized_cert_logs_identity(
    stub, check_request, trusted_client_cert_pem, caplog
):
    """A verified client cert produces an Authorized log line whose extra
    carries the parsed identity (common_name + clientAuth EKU)."""
    import logging

    with caplog.at_level(logging.INFO, logger="envoy_authz.app"):
        response = stub.Check(
            check_request(
                host="other.example.com",
                path="/",
                client_cert_pem=trusted_client_cert_pem,
            )
        )

    assert response.status.code == code_pb2.OK
    identity_records = [
        r for r in caplog.records if getattr(r, "identity", None) is not None
    ]
    assert identity_records, "expected an Authorized log record with identity"
    identity = identity_records[-1].identity
    assert identity["common_name"] == "trusted-client.ha.apps.somemissing.info"
    assert "clientAuth" in identity["extended_key_usages"]
```

Add the `code_pb2` import if not already present at the top of the file — it is (`from google.rpc import code_pb2`).

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/integration/test_check.py::test_authorized_cert_logs_identity -q`
Expected: FAIL (no log record carries an `identity` attribute yet).

- [ ] **Step 3: Update imports in app.py**

In `envoy_authz/app.py`, add the identity import alongside the existing local imports (after the third-party imports):

```python
from envoy_authz.identity import parse_client_identity
```

- [ ] **Step 4: Refactor verify_client_cert to return the verified cert**

Replace the existing `verify_client_cert` function body with:

```python
def verify_client_cert(
    cert_pem: str, store: crypto.X509Store
) -> x509.Certificate | None:
    """Verify a client certificate against the CA + CRL and require the
    clientAuth EKU. Returns the verified certificate, or None on any failure.
    """
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())
        crypto.X509StoreContext(store, cert).verify_certificate()

        crypto_cert = cert.to_cryptography()
        eku = crypto_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
            return None

        return crypto_cert
    except Exception:
        logger.exception("Client cert verification failed")
        return None
```

- [ ] **Step 5: Update Check to use the returned cert and log identity**

In `Check`, replace the `allowed = (...)` assignment and the `if allowed:` logging with:

```python
        # Verify the client cert once (if provided) and reuse the result.
        raw_certificate = request.attributes.source.certificate
        client_cert = None
        if raw_certificate:
            client_cert = verify_client_cert(
                urllib.parse.unquote(raw_certificate),
                self._config.ha_ca_store,
            )

        # Figure out if a request should be allowed (can be arbitrary criteria)
        allowed = (
            # Requests to the frigate metrics endpoint don't need auth
            request.attributes.request.http.host == FRIGATE_HOST
            and path == "/api/metrics"
        ) or (
            # Requests should contain a valid client certificate from the
            # Home Assistant CA
            client_cert is not None
        )

        if allowed:
            log_extra: dict = {}
            # Parsing is best-effort and must never affect the decision.
            if client_cert is not None:
                try:
                    log_extra["identity"] = parse_client_identity(
                        client_cert
                    ).model_dump(exclude_none=True)
                except Exception:
                    logger.exception("Failed to parse client identity")
            logger.info("✓ Authorized", extra=log_extra)
```

(The `return_headers` block and the rest of the `if allowed:` body below this point are unchanged; only the `allowed` computation and the single `logger.info("✓ Authorized")` line are replaced.)

- [ ] **Step 6: Run the new test to verify it passes**

Run: `.venv/bin/python -m pytest tests/integration/test_check.py::test_authorized_cert_logs_identity -q`
Expected: PASS.

- [ ] **Step 7: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all PASS (existing allow/deny behavior unchanged).

- [ ] **Step 8: Lint/format**

Run: `.venv/bin/python -m pre_commit run --files envoy_authz/app.py tests/integration/test_check.py`
Expected: ruff + ruff-format pass.

- [ ] **Step 9: Commit**

```bash
git add envoy_authz/app.py tests/integration/test_check.py
git commit -m "feat: parse and log client identity on authorized requests"
```

---

### Task 5: Open the pull request

**Files:** none (git/gh only).

- [ ] **Step 1: Push the branch**

Run: `git push -u origin feat/client-cert-identity`

- [ ] **Step 2: Open the PR**

Run `gh pr create` with a title like `feat: extract and log client certificate identity` and a body summarizing: the new `ClientIdentity` model + `parse_client_identity`, best-effort per-field validation, log-only wiring, the `verify_client_cert` return-type change, the displayName OID correction, and the dependency changes. Link the design doc and plan.

Expected: PR URL printed.

---

## Self-Review

**Spec coverage:**
- New module + model + extractor → Tasks 2, 3. ✓
- Every field optional, best-effort drop-and-log → Task 2 (model), Task 3 (`_validate_scalar`/`_validate_list`). ✓
- Field/validation table (all 13 fields, bounds) → Task 2 model + Task 3 extraction. ✓
- displayName correct OID → Task 3 `_OID_DISPLAY_NAME`, test `test_display_name_read_from_correct_oid_not_2_5_4_53`. ✓
- Custom email validator (no email-validator dep) → Task 2 `_validate_email`. ✓
- `verify_client_cert` returns cert; parse only verified certs; log-only; parse failure never affects decision → Task 4. ✓
- Dependencies (pydantic runtime, cryptography promoted) → Task 1. ✓
- Testing (all-fields, bare, multi-OU, multi-email split, invalid email dropped, over-length CN, displayName OID, key usage/EKU/basic constraints, integration log) → Tasks 3 + 4. ✓

**Placeholder scan:** No TBD/TODO; all code steps contain full code. ✓

**Type consistency:** `parse_client_identity(cert) -> ClientIdentity`, `verify_client_cert(...) -> x509.Certificate | None`, shared `CommonName/Name/DisplayName/OrgName/Uid/Email` aliases used identically in model and adapters. ✓
