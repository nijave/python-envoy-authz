"""Best-effort extraction of identity attributes from a verified X.509 client
certificate into a validated Pydantic model.

Every attribute is optional, so a certificate may carry any subset.
`ClientIdentity` validates each field independently and drops (logging) any
value that fails, so one malformed attribute never loses the rest.
"""

import logging
from typing import Annotated, Any

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StringConstraints,
    ValidationError,
    ValidationInfo,
    WrapValidator,
    field_validator,
)
from pydantic_core.core_schema import ValidatorFunctionWrapHandler

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


# Shared constraint aliases — single source of truth for per-field bounds.
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


# Sentinel marking a list item that failed validation, pruned by `_prune`.
_DROP = object()


def _drop_item(
    value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
) -> Any:
    """Mark (logging) an invalid list item for pruning, keeping the rest."""
    try:
        return handler(value)
    except ValidationError as exc:
        logger.warning(
            "Dropping invalid client-cert field %s: %s",
            info.field_name,
            exc.errors()[0]["msg"],
        )
        return _DROP


def _prune(values: list[Any]) -> list[Any]:
    return [v for v in values if v is not _DROP]


# Lists holding only the items that passed validation; invalid items are
# dropped rather than rejecting the whole list.
ValidatedOrgUnits = Annotated[
    list[Annotated[OrgName, WrapValidator(_drop_item)]], AfterValidator(_prune)
]
ValidatedEmails = Annotated[
    list[Annotated[Email, WrapValidator(_drop_item)]], AfterValidator(_prune)
]


class ClientIdentity(BaseModel):
    """Identity and key-policy attributes extracted from a client certificate.

    Best-effort: every field is optional, and any value that fails validation
    is dropped (logging) rather than raising, so one malformed attribute never
    loses the rest.
    """

    common_name: CommonName | None = None
    surname: Name | None = None
    given_name: Name | None = None
    display_name: DisplayName | None = None
    organization: OrgName | None = None
    organizational_units: ValidatedOrgUnits = Field(default_factory=list)
    uid: Uid | None = None
    primary_email: Email | None = None
    additional_email_addresses: ValidatedEmails = Field(default_factory=list)
    is_ca: bool | None = None
    path_length: Annotated[int, Field(ge=0)] | None = None
    key_usages: list[str] = Field(default_factory=list)
    extended_key_usages: list[str] = Field(default_factory=list)

    @field_validator("*", mode="wrap")
    @classmethod
    def _drop_invalid(
        cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> Any:
        """Drop (logging) any scalar that fails validation to None. All fields
        are optional so None is valid; list fields prune bad items internally
        and don't raise here."""
        try:
            return handler(value)
        except ValidationError as exc:
            logger.warning(
                "Dropping invalid client-cert field %s: %s",
                info.field_name,
                exc.errors()[0]["msg"],
            )
            return None


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


def parse_client_identity(cert: x509.Certificate) -> ClientIdentity:
    """Read the raw attributes off a verified cert into a `ClientIdentity`."""
    subject = cert.subject
    is_ca, path_length = _basic_constraints(cert)
    emails = _san_emails(cert)

    return ClientIdentity.model_validate(
        {
            "common_name": _first_attr(subject, NameOID.COMMON_NAME),
            "surname": _first_attr(subject, NameOID.SURNAME),
            "given_name": _first_attr(subject, NameOID.GIVEN_NAME),
            "display_name": _first_attr(subject, _OID_DISPLAY_NAME),
            "organization": _first_attr(subject, NameOID.ORGANIZATION_NAME),
            "organizational_units": _all_str_attrs(
                subject, NameOID.ORGANIZATIONAL_UNIT_NAME
            ),
            "uid": _first_attr(subject, NameOID.USER_ID),
            "primary_email": emails[0] if emails else None,
            "additional_email_addresses": emails[1:],
            "is_ca": is_ca,
            "path_length": path_length,
            "key_usages": _key_usages(cert),
            "extended_key_usages": _extended_key_usages(cert),
        }
    )
