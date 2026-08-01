"""End-to-end federation test against a live Vikunja stack.

Skipped unless ``RUN_INTEGRATION=1``. Bring up the stack with::

    docker compose -f docker-compose.vikunja.yml up -d --build
    RUN_INTEGRATION=1 \\
        TLS_CA=<server-ca.pem> \\
        TLS_CLIENT_CERT=<client.crt> TLS_CLIENT_KEY=<client.key> \\
        poetry run pytest tests/integration/test_integration_vikunja.py -v

The mTLS material is operator-supplied (not the in-process test PKI, whose key
is never exposed and whose CA is random per session). The client cert must be
signed by the CA the federator trusts (``HA_CA_CERTIFICATE`` in the compose) and
the server cert's CA is ``TLS_CA``.
"""

import os
import urllib.parse

import grpc
import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("RUN_INTEGRATION"),
        reason="set RUN_INTEGRATION=1 to run integration tests",
    ),
]


def test_check_federates_to_vikunja():
    from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc

    tls_ca = os.environ.get("TLS_CA")
    client_cert = os.environ.get("TLS_CLIENT_CERT")
    client_key = os.environ.get("TLS_CLIENT_KEY")
    if not (tls_ca and client_cert and client_key):
        pytest.fail(
            "RUN_INTEGRATION=1 set but TLS_CA / TLS_CLIENT_CERT / TLS_CLIENT_KEY "
            "not all provided (server CA PEM, mTLS client cert PEM, client key PEM)"
        )

    channel_creds = grpc.ssl_channel_credentials(
        root_certificates=tls_ca.encode(),
        certificate_chain=client_cert.encode(),
        private_key=client_key.encode(),
    )
    request = external_auth_pb2.CheckRequest()
    # The same client cert (URL-encoded) is what the federator verifies against
    # HA_CA_CERTIFICATE to derive the subject.
    request.attributes.source.certificate = urllib.parse.quote(client_cert, safe="")
    request.attributes.request.http.host = "vikunja.local"
    request.attributes.request.http.path = "/api/v1"

    with grpc.secure_channel("localhost:9090", channel_creds) as channel:
        stub = external_auth_pb2_grpc.AuthorizationStub(channel)
        resp = stub.Check(request, timeout=30)

    # The federator minted (or reused) a Vikunja session and injected a bearer.
    assert resp.HasField("ok_response")
    added = {h.header.key: h.header.value for h in resp.ok_response.headers}
    assert added["Authorization"].startswith("Bearer ")
