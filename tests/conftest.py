"""Test fixtures for envoy_authz integration tests.

This module's top-level code runs at pytest conftest load time, which
happens before any test module is imported. It generates an ephemeral
PKI, sets the env vars that `envoy_authz.app` reads at import time, and
*then* imports the app so its module-level globals (HA_CA_STORE,
FRIGATE_X_PROXY_SECRET) are built from the test values.
"""

import datetime
import os
import socket
import urllib.parse
from concurrent import futures
from contextlib import closing

import grpc
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


FRIGATE_TEST_SECRET = "test-frigate-secret-abc123"


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _generate_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
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
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _build_signed_cert(
    common_name: str,
    issuer_key: rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _generate_key()
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )
    return key, cert


def _build_server_cert(
    common_name: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Self-signed server cert with a SubjectAltName for TLS validation."""
    key = _generate_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
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

_TRUSTED_CLIENT_KEY, _TRUSTED_CLIENT_CERT = _build_signed_cert(
    "trusted-client", _TRUSTED_CA_KEY, _TRUSTED_CA
)
_UNTRUSTED_CLIENT_KEY, _UNTRUSTED_CLIENT_CERT = _build_signed_cert(
    "untrusted-client", _UNTRUSTED_CA_KEY, _UNTRUSTED_CA
)
_SELF_SIGNED_CLIENT_KEY, _SELF_SIGNED_CLIENT_CERT = _build_ca(
    "self-signed-client"
)

# Set env vars BEFORE importing the app module
os.environ["HA_CA_CERTIFICATE"] = _pem(_TRUSTED_CA)
os.environ["FRIGATE_X_PROXY_SECRET"] = FRIGATE_TEST_SECRET

# Now safe to import — triggers the global HA_CA_STORE build
from envoy_authz import app  # noqa: E402, F401

from envoy.service.auth.v3 import (  # noqa: E402
    external_auth_pb2,
    external_auth_pb2_grpc,
)


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def grpc_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(
        app.AuthorizationService(), server
    )
    credentials = grpc.ssl_server_credentials(
        [(_pem_key(_SERVER_KEY), _pem_bytes(_SERVER_CERT))]
    )
    port = server.add_secure_port("[::]:0", credentials)
    server.start()
    try:
        yield port
    finally:
        server.stop(grace=None)


@pytest.fixture
def stub(grpc_server):
    creds = grpc.ssl_channel_credentials(
        root_certificates=_pem_bytes(_SERVER_CERT)
    )
    options = (("grpc.ssl_target_name_override", "localhost"),)
    channel = grpc.secure_channel(
        f"localhost:{grpc_server}", creds, options=options
    )
    try:
        yield external_auth_pb2_grpc.AuthorizationStub(channel)
    finally:
        channel.close()


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
                client_cert_pem
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
def frigate_secret() -> str:
    return FRIGATE_TEST_SECRET
