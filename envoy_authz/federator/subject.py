"""Deterministic subject derivation from a verified client certificate.

Replaces python-client-idp's in-memory-counter get_or_create_user_by_email:
the subject is the cert's `uid` (the USER_ID RDN). The homelab PKI issues one
cert per device (see homelab-pki tofu) whose CN is `<device>.<domain>` but
whose uid is the PERSON (e.g. every one of nick's devices carries uid=nick).
Keying the downstream identity on uid — not the CN or the cert's public key —
means all of a person's devices map to ONE Vikunja user, and renewing/reissuing
a cert does not orphan it. A cert without a uid is rejected: provisioning off a
per-device CN would fork one person into a new user per device (and per renewal).

Attribute extraction is delegated to `envoy_authz.identity.parse_client_identity`
so the email that travels downstream is the SAME validated, lowercased value the
identity log line reports. Deriving it independently here previously let a
mixed-case or malformed rfc822Name reach Vikunja user provisioning unnormalized.
"""

from typing import NamedTuple

from cryptography import x509

from ..identity import ClientIdentity, parse_client_identity


class MissingUidError(ValueError):
    """The verified client cert has no uid (USER_ID RDN), so no stable identity
    can be derived. The homelab PKI always issues one; a cert without it is not
    provisionable and must be rejected rather than keyed on its per-device CN."""


class Subject(NamedTuple):
    sub: str
    email: str | None
    name: str


def derive_subject(
    cert: x509.Certificate, identity: ClientIdentity | None = None
) -> Subject:
    """Turn a verified cert into a stable subject + email + display name.

    `sub` is the cert's uid (USER_ID RDN): the person, shared across their
    devices and stable across cert renewal. Raises `MissingUidError` when the
    cert carries no uid.

    `identity` may be supplied by a caller that already parsed the cert (the
    gRPC servicer does, for logging) to avoid re-walking the extensions.
    """
    if identity is None:
        identity = parse_client_identity(cert)

    uid = identity.uid
    if not uid:
        raise MissingUidError("client certificate has no uid (USER_ID RDN)")

    # Validated + lowercased by identity.Email; None if it failed validation,
    # which is deliberate — better to deny than to provision a malformed user.
    email = identity.primary_email

    # Display name only — the CN is a per-device host name, never the person,
    # so it is deliberately NOT a source here.
    name = identity.display_name or _join_full_name(identity) or uid
    return Subject(sub=uid, email=email, name=name)


def _join_full_name(identity: ClientIdentity) -> str | None:
    given, surname = identity.given_name, identity.surname
    if given and surname:
        return f"{given} {surname}"
    return given or surname
