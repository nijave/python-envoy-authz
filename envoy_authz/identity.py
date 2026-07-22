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
