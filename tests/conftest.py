"""Test fixtures for envoy_authz integration tests.

Generates an ephemeral PKI and builds a `Config` directly (no env vars
needed — the app module has no import-time side effects).
"""

import datetime
import urllib.parse
from concurrent import futures

import grpc
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from envoy_authz.config import Config, build_store
from envoy_authz.grpc_service import register_services
from grpc_health.v1 import health_pb2, health_pb2_grpc
from envoy.service.auth.v3 import (
    external_auth_pb2,
    external_auth_pb2_grpc,
)


FRIGATE_TEST_SECRET = "test-frigate-secret-abc123"


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ca_name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "homelab"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "apps"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _build_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _generate_key()
    name = _ca_name(common_name)
    public_key = key.public_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _build_signed_cert(
    common_name: str,
    issuer_key: rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
    *,
    eku: list[x509.ObjectIdentifier] | None = None,
    san_emails: list[str] | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Leaf client cert signed by the given CA. Mirrors the extension
    set used by real Home Assistant-issued client certs: BasicConstraints
    CA:FALSE, KeyUsage (digitalSignature, keyEncipherment), ExtendedKeyUsage
    (clientAuth), SubjectKeyIdentifier, AuthorityKeyIdentifier, and a DNS
    SubjectAlternativeName matching the CN."""
    if eku is None:
        eku = [ExtendedKeyUsageOID.CLIENT_AUTH]
    key = _generate_key()
    public_key = key.public_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
            x509.ExtendedKeyUsage(eku),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()
            ),
            critical=False,
        )
    )
    san_names: list[x509.GeneralName] = [x509.DNSName(common_name)]
    if san_emails:
        san_names.extend(x509.RFC822Name(e) for e in san_emails)
    cert = builder.add_extension(
        x509.SubjectAlternativeName(san_names),
        critical=False,
    ).sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return key, cert


def _build_self_signed_leaf(
    common_name: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Self-signed client leaf cert. Carries the same extension shape
    as `_build_signed_cert` (CA:FALSE, KeyUsage, EKU=clientAuth, SAN)
    but is its own issuer, so the trusted CA store rejects it."""
    key = _generate_key()
    public_key = key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _build_server_cert(
    common_name: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Self-signed server cert with a SubjectAltName for TLS validation."""
    key = _generate_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _pem_bytes(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---- Generate the PKI bundle at conftest load (before app import) ----

_TRUSTED_CA_KEY, _TRUSTED_CA = _build_ca("test-trusted-ca")
_UNTRUSTED_CA_KEY, _UNTRUSTED_CA = _build_ca("test-untrusted-ca")
_SERVER_KEY, _SERVER_CERT = _build_server_cert("localhost")

_, _TRUSTED_CLIENT_CERT = _build_signed_cert(
    "trusted-client.ha.apps.somemissing.info", _TRUSTED_CA_KEY, _TRUSTED_CA
)
_, _UNTRUSTED_CLIENT_CERT = _build_signed_cert(
    "untrusted-client.ha.apps.somemissing.info",
    _UNTRUSTED_CA_KEY,
    _UNTRUSTED_CA,
)
_, _SELF_SIGNED_CLIENT_CERT = _build_self_signed_leaf(
    "self-signed-client.ha.apps.somemissing.info"
)
_, _WRONG_EKU_CLIENT_CERT = _build_signed_cert(
    "wrong-eku-client.ha.apps.somemissing.info",
    _TRUSTED_CA_KEY,
    _TRUSTED_CA,
    eku=[ExtendedKeyUsageOID.SERVER_AUTH],
)
_, _REVOKED_CLIENT_CERT = _build_signed_cert(
    "revoked-client.ha.apps.somemissing.info", _TRUSTED_CA_KEY, _TRUSTED_CA
)
_EMAIL_CLIENT_KEY, _EMAIL_CLIENT_CERT = _build_signed_cert(
    "email-client.ha.apps.somemissing.info",
    _TRUSTED_CA_KEY,
    _TRUSTED_CA,
    san_emails=["user@example.com"],
)
# A SAN rfc822Name that is NOT already normalized, to pin that the email
# travelling downstream is lowercased the same way the identity log line is.
_, _MIXED_CASE_EMAIL_CERT = _build_signed_cert(
    "mixed-case.ha.apps.somemissing.info",
    _TRUSTED_CA_KEY,
    _TRUSTED_CA,
    san_emails=["Alice@Example.COM"],
)


def _build_crl(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    revoked_serials: list[int],
    *,
    expired: bool = False,
) -> x509.CertificateRevocationList:
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        last_update = now - datetime.timedelta(days=2)
        next_update = now - datetime.timedelta(days=1)
    else:
        last_update = now
        next_update = now + datetime.timedelta(days=30)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(last_update)
        .next_update(next_update)
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .build()
        )
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


_CRL = _build_crl(_TRUSTED_CA_KEY, _TRUSTED_CA, [_REVOKED_CLIENT_CERT.serial_number])


@pytest.fixture(scope="session")
def ha_config() -> Config:
    from envoy_authz.config import Settings

    store = build_store(
        _pem(_TRUSTED_CA),
        _CRL.public_bytes(serialization.Encoding.PEM).decode(),
    )
    settings = Settings(
        frigate_x_proxy_secret=FRIGATE_TEST_SECRET,
        ha_ca_certificate=_pem(_TRUSTED_CA),
        ha_crl=_CRL.public_bytes(serialization.Encoding.PEM).decode(),
        idp_issuer="https://idp.test",
        secret_key="test-secret-key",
    )
    return Config(settings=settings, ha_ca_store=store)


@pytest.fixture(scope="session")
def grpc_server(ha_config):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    health_servicer = register_services(server, ha_config)
    credentials = grpc.ssl_server_credentials(
        [(_pem_key(_SERVER_KEY), _pem_bytes(_SERVER_CERT))]
    )
    port = server.add_secure_port("[::]:0", credentials)
    server.start()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    try:
        yield port
    finally:
        server.stop(grace=None)


@pytest.fixture
def channel(grpc_server):
    creds = grpc.ssl_channel_credentials(root_certificates=_pem_bytes(_SERVER_CERT))
    options = (("grpc.ssl_target_name_override", "localhost"),)
    ch = grpc.secure_channel(f"localhost:{grpc_server}", creds, options=options)
    try:
        yield ch
    finally:
        ch.close()


@pytest.fixture
def stub(channel):
    return external_auth_pb2_grpc.AuthorizationStub(channel)


@pytest.fixture
def health_stub(channel):
    return health_pb2_grpc.HealthStub(channel)


@pytest.fixture(scope="session")
def check_request():
    """Returns a builder for `CheckRequest` messages."""

    def _build(*, host: str, path: str, client_cert_pem: str | None = None):
        request = external_auth_pb2.CheckRequest()
        request.attributes.request.http.host = host
        request.attributes.request.http.path = path
        if client_cert_pem is not None:
            # Envoy URL-encodes the cert PEM in source.certificate
            request.attributes.source.certificate = urllib.parse.quote(
                client_cert_pem, safe=""
            )
        return request

    return _build


@pytest.fixture(scope="session")
def trusted_client_cert_pem() -> str:
    return _pem(_TRUSTED_CLIENT_CERT)


@pytest.fixture(scope="session")
def untrusted_client_cert_pem() -> str:
    return _pem(_UNTRUSTED_CLIENT_CERT)


@pytest.fixture(scope="session")
def self_signed_client_cert_pem() -> str:
    return _pem(_SELF_SIGNED_CLIENT_CERT)


@pytest.fixture(scope="session")
def wrong_eku_client_cert_pem() -> str:
    return _pem(_WRONG_EKU_CLIENT_CERT)


@pytest.fixture(scope="session")
def revoked_client_cert_pem() -> str:
    return _pem(_REVOKED_CLIENT_CERT)


@pytest.fixture(scope="session")
def email_client_cert_pem() -> str:
    return _pem(_EMAIL_CLIENT_CERT)


@pytest.fixture(scope="session")
def mixed_case_email_cert_pem() -> str:
    return _pem(_MIXED_CASE_EMAIL_CERT)


@pytest.fixture(scope="session")
def ca_cert_pem() -> str:
    return _pem(_TRUSTED_CA)


@pytest.fixture(scope="session")
def crl_pem() -> str:
    return _CRL.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="session")
def expired_crl_pem() -> str:
    crl = _build_crl(
        _TRUSTED_CA_KEY,
        _TRUSTED_CA,
        [_REVOKED_CLIENT_CERT.serial_number],
        expired=True,
    )
    return crl.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="session")
def frigate_secret() -> str:
    return FRIGATE_TEST_SECRET


OP_PROVIDERS_YAML = """
providers:
  vikunja:
    hosts: ["vikunja.test"]
    client_id: "vikunja"
    client_secret: "vikunja-secret"
    redirect_url: "http://localhost:3456/auth/openid/broker"
    api_base: "http://localhost:3456"
    provider_key: "broker"
    scope: "openid profile email"
"""


OP_TEST_ISSUER = "https://idp.test"


def _federation_settings(providers_file: str):
    """The resolved federation config the OP/federator are wired from.

    Built directly rather than via env vars: `store`/`op.runtime` are configured
    explicitly at startup now, so tests do not need a full valid environment
    just to exercise the OP.
    """
    from envoy_authz.config import FederationSettings

    return FederationSettings(
        idp_issuer=OP_TEST_ISSUER,
        secret_key="test-secret-key",
        providers_file=providers_file,
        code_ttl_seconds=10,
    )


@pytest.fixture
def op_client(tmp_path, monkeypatch):
    """A FastAPI TestClient with the OP mounted, store seeded, keys generated."""
    from fastapi.testclient import TestClient

    # TestClient uses http://testserver, which authlib would reject as
    # insecure transport; allow http for the in-process OP tests.
    monkeypatch.setenv("AUTHLIB_INSECURE_TRANSPORT", "1")

    from envoy_authz.federator import providers
    from envoy_authz.federator.store import _reset, seed
    from envoy_authz.http_app import create_app

    p = tmp_path / "providers.yaml"
    p.write_text(OP_PROVIDERS_YAML)
    providers.load_providers(str(p))
    _reset()
    seed()

    key_path = str(tmp_path / "op_key.pem")
    app = create_app(op_key_path=key_path, federation=_federation_settings(str(p)))
    return TestClient(app)
