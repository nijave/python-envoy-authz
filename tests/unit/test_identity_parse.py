"""Unit tests for parse_client_identity against built certificates."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from envoy_authz.identity import parse_client_identity

_DISPLAY_NAME_OID = ObjectIdentifier("2.16.840.1.113730.3.1.241")


_DEFAULT_KEY_USAGE = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=True,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)


def _sign_self_signed(
    name_attrs: list[x509.NameAttribute],
    extensions: list[tuple[x509.ExtensionType, bool]],
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name(name_attrs)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(private_key=key, algorithm=hashes.SHA256())


def _build_cert(
    *,
    name_attrs: list[x509.NameAttribute],
    san_emails: list[str] | None = None,
    eku: list[ObjectIdentifier] | None = None,
    ca: bool = False,
    key_usage: x509.KeyUsage | None = None,
) -> x509.Certificate:
    extensions: list[tuple[x509.ExtensionType, bool]] = [
        (x509.BasicConstraints(ca=ca, path_length=None), True),
        (key_usage or _DEFAULT_KEY_USAGE, True),
        (x509.ExtendedKeyUsage(eku or [ExtendedKeyUsageOID.CLIENT_AUTH]), False),
    ]
    if san_emails:
        extensions.append(
            (
                x509.SubjectAlternativeName([x509.RFC822Name(e) for e in san_emails]),
                False,
            )
        )
    return _sign_self_signed(name_attrs, extensions)


def _build_bare_cert(name_attrs: list[x509.NameAttribute]) -> x509.Certificate:
    """A cert carrying only the subject DN — no SAN, EKU, KeyUsage, or
    BasicConstraints extensions."""
    return _sign_self_signed(name_attrs, [])


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


def test_over_length_field_dropped_others_kept():
    # cryptography enforces X.520 length bounds (e.g. CN <= 64) at build time,
    # so an over-length scalar is exercised via displayName, whose OID
    # cryptography does not length-bound but our model caps at 256.
    cert = _build_cert(
        name_attrs=[
            x509.NameAttribute(NameOID.COMMON_NAME, "cn"),
            x509.NameAttribute(_DISPLAY_NAME_OID, "x" * 257),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME"),
        ],
    )
    identity = parse_client_identity(cert)
    assert identity.display_name is None
    assert identity.common_name == "cn"
    assert identity.organization == "ACME"


def test_extended_key_usage_unknown_oid_falls_back_to_dotted():
    cert = _build_cert(
        name_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "cn")],
        eku=[ObjectIdentifier("1.3.6.1.4.1.99999.1")],
    )
    identity = parse_client_identity(cert)
    assert identity.extended_key_usages == ["1.3.6.1.4.1.99999.1"]


def test_cert_without_extensions_yields_empty_defaults():
    # A cert with no SAN / EKU / KeyUsage / BasicConstraints extensions must
    # parse cleanly with all extension-derived fields left empty / None.
    cert = _build_bare_cert(
        name_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "bare")],
    )
    identity = parse_client_identity(cert)
    assert identity.common_name == "bare"
    assert identity.is_ca is None
    assert identity.path_length is None
    assert identity.key_usages == []
    assert identity.extended_key_usages == []
    assert identity.primary_email is None
    assert identity.additional_email_addresses == []


def test_encipher_and_decipher_only_read_when_key_agreement_set():
    # encipher_only / decipher_only are only defined when key_agreement is set.
    cert = _build_cert(
        name_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "cn")],
        key_usage=x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=True,
            decipher_only=False,
        ),
    )
    identity = parse_client_identity(cert)
    assert "key_agreement" in identity.key_usages
    assert "encipher_only" in identity.key_usages
    assert "decipher_only" not in identity.key_usages
