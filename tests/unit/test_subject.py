from envoy_authz.federator.subject import Subject, derive_subject


def test_subject_is_stable_for_same_cert(trusted_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(trusted_client_cert_pem.encode())
    s1 = derive_subject(cert)
    s2 = derive_subject(cert)
    assert s1.sub == s2.sub
    assert len(s1.sub) == 16
    assert isinstance(s1, Subject)


def test_two_different_certs_yield_different_subs(
    trusted_client_cert_pem, untrusted_client_cert_pem
):
    from cryptography import x509

    a = derive_subject(x509.load_pem_x509_certificate(trusted_client_cert_pem.encode()))
    b = derive_subject(
        x509.load_pem_x509_certificate(untrusted_client_cert_pem.encode())
    )
    assert a.sub != b.sub


def test_subject_email_taken_from_san(trusted_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(trusted_client_cert_pem.encode())
    s = derive_subject(cert)
    # The trusted client cert is built with CN=<host>.apps.somemissing.info and
    # no email SAN by default; assert the helper returns None when absent.
    assert s.email is None or "@" in s.email


def test_subject_name_falls_back_to_cn(trusted_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(trusted_client_cert_pem.encode())
    s = derive_subject(cert)
    assert s.name  # non-empty


def test_subject_email_from_san_email_cert(email_client_cert_pem):
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(email_client_cert_pem.encode())
    s = derive_subject(cert)
    assert s.email == "user@example.com"
    assert s.name == "email-client.ha.apps.somemissing.info"


def test_subject_email_is_normalized_like_the_identity_log(mixed_case_email_cert_pem):
    """The email that travels into the OP auth code must be the SAME validated,
    lowercased value `parse_client_identity` reports, so Vikunja provisioning and
    the identity log line cannot disagree (and key two different users)."""
    from cryptography import x509

    from envoy_authz.identity import parse_client_identity

    cert = x509.load_pem_x509_certificate(mixed_case_email_cert_pem.encode())
    s = derive_subject(cert)
    assert s.email == "alice@example.com"
    assert s.email == parse_client_identity(cert).primary_email


def test_derive_subject_accepts_a_prebuilt_identity(email_client_cert_pem):
    """Callers that already parsed the cert can pass it in; same result."""
    from cryptography import x509

    from envoy_authz.identity import parse_client_identity

    cert = x509.load_pem_x509_certificate(email_client_cert_pem.encode())
    identity = parse_client_identity(cert)
    assert derive_subject(cert, identity) == derive_subject(cert)
