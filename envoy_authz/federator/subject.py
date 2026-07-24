"""Deterministic subject derivation from a verified client certificate.

Replaces python-client-idp's in-memory-counter get_or_create_user_by_email:
the subject is derived from the cert's subject DN + SubjectPublicKeyInfo, so it
is stable across restarts (Vikunja's user persists; a changing sub would
orphan it).

Attribute extraction is delegated to `envoy_authz.identity.parse_client_identity`
so the email that travels downstream is the SAME validated, lowercased value the
identity log line reports. Deriving it independently here previously let a
mixed-case or malformed rfc822Name reach Vikunja user provisioning unnormalized.
"""

import hashlib
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..identity import ClientIdentity, parse_client_identity


class Subject(NamedTuple):
    sub: str
    email: str | None
    name: str


def derive_subject(
    cert: x509.Certificate, identity: ClientIdentity | None = None
) -> Subject:
    """Turn a verified cert into a stable subject + email + display name.

    `sub` is a 16-char hex SHA-256 over the subject DN DER concatenated with
    the SubjectPublicKeyInfo DER — identifying both who and which key.

    `identity` may be supplied by a caller that already parsed the cert (the
    gRPC servicer does, for logging) to avoid re-walking the extensions.
    """
    subject_der = cert.subject.public_bytes()
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(subject_der + spki_der).hexdigest()[:16]

    if identity is None:
        identity = parse_client_identity(cert)

    # Validated + lowercased by identity.Email; None if it failed validation,
    # which is deliberate — better to deny than to provision a malformed user.
    email = identity.primary_email

    name = (
        identity.common_name
        or identity.display_name
        or _join_full_name(identity)
        or (email.split("@", 1)[0] if email else None)
        or digest
    )
    return Subject(sub=digest, email=email, name=name)


def _join_full_name(identity: ClientIdentity) -> str | None:
    given, surname = identity.given_name, identity.surname
    if given and surname:
        return f"{given} {surname}"
    return given or surname
