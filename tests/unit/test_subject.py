import pytest

from envoy_authz.federator.subject import MissingUidError, Subject, derive_subject


def _cert(pem: str):
    from cryptography import x509

    return x509.load_pem_x509_certificate(pem.encode())


def test_subject_sub_is_the_cert_uid_not_the_cn(trusted_client_cert_pem):
    # The trusted cert has CN=trusted-client.ha.apps... but uid=nick. The
    # subject must key on the uid, never the per-device CN.
    s = derive_subject(_cert(trusted_client_cert_pem))
    assert s.sub == "nick"
    assert isinstance(s, Subject)


def test_subject_is_stable_for_same_cert(trusted_client_cert_pem):
    cert = _cert(trusted_client_cert_pem)
    assert derive_subject(cert).sub == derive_subject(cert).sub == "nick"


def test_same_person_different_device_yields_same_sub(
    trusted_client_cert_pem, trusted_client_cert_other_device_pem
):
    # Two certs, same uid but different device CNs, must map to ONE subject —
    # otherwise every device forks a new downstream user.
    a = derive_subject(_cert(trusted_client_cert_pem))
    b = derive_subject(_cert(trusted_client_cert_other_device_pem))
    assert a.sub == b.sub == "nick"


def test_two_different_uids_yield_different_subs(
    trusted_client_cert_pem, untrusted_client_cert_pem
):
    a = derive_subject(_cert(trusted_client_cert_pem))
    b = derive_subject(_cert(untrusted_client_cert_pem))
    assert a.sub != b.sub


def test_cert_without_uid_is_rejected(no_uid_client_cert_pem):
    with pytest.raises(MissingUidError):
        derive_subject(_cert(no_uid_client_cert_pem))


def test_subject_name_prefers_display_name_over_cn(trusted_client_cert_pem):
    # displayName=Nick V is the human name; the CN (a host name) must not leak
    # into the downstream `name` claim.
    s = derive_subject(_cert(trusted_client_cert_pem))
    assert s.name == "Nick V"


def test_subject_name_falls_back_to_uid_when_no_display_name(
    untrusted_client_cert_pem,
):
    # The untrusted cert has only CN + the default uid (its CN's first label)
    # and no displayName/givenName/surname, so the name falls back to the uid.
    s = derive_subject(_cert(untrusted_client_cert_pem))
    assert s.name == s.sub == "untrusted-client"


def test_subject_email_taken_from_san(trusted_client_cert_pem):
    s = derive_subject(_cert(trusted_client_cert_pem))
    # No email SAN on the trusted cert; the helper returns None when absent.
    assert s.email is None or "@" in s.email


def test_subject_email_from_san_email_cert(email_client_cert_pem):
    s = derive_subject(_cert(email_client_cert_pem))
    assert s.email == "user@example.com"
    assert s.sub == "email-client"  # uid defaults to the CN's first label


def test_subject_email_is_normalized_like_the_identity_log(mixed_case_email_cert_pem):
    """The email that travels into the OP auth code must be the SAME validated,
    lowercased value `parse_client_identity` reports, so Vikunja provisioning and
    the identity log line cannot disagree (and key two different users)."""
    from envoy_authz.identity import parse_client_identity

    cert = _cert(mixed_case_email_cert_pem)
    s = derive_subject(cert)
    assert s.email == "alice@example.com"
    assert s.email == parse_client_identity(cert).primary_email


def test_derive_subject_accepts_a_prebuilt_identity(email_client_cert_pem):
    """Callers that already parsed the cert can pass it in; same result."""
    from envoy_authz.identity import parse_client_identity

    cert = _cert(email_client_cert_pem)
    identity = parse_client_identity(cert)
    assert derive_subject(cert, identity) == derive_subject(cert)
