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
# reused by both the model below and the per-field TypeAdapters in the extractor.
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
Email = Annotated[
    str, StringConstraints(strip_whitespace=True), AfterValidator(_validate_email)
]


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
    for attr in name.get_attributes_for_oid(oid):
        if isinstance(attr.value, str):
            return attr.value
    return None


def _all_str_attrs(name: x509.Name, oid: ObjectIdentifier) -> list[str]:
    return [
        a.value for a in name.get_attributes_for_oid(oid) if isinstance(a.value, str)
    ]


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
