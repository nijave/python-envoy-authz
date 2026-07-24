"""End-to-end federation test against a live Vikunja stack.

Skipped unless ``RUN_INTEGRATION=1``. Bring up the stack with::

    docker compose -f docker-compose.vikunja.yml up -d --build
    RUN_INTEGRATION=1 TLS_CA=<server-ca.pem> TLS_CLIENT_KEY=<client.key> \\
        poetry run pytest tests/integration/test_integration_vikunja.py -v

The mTLS client cert (``trusted_email_cert_pem``) is signed by the test PKI CA,
so the federator's ``HA_CA_CERTIFICATE`` must trust that same CA for the request
to pass the mTLS gate and reach the federation ladder.
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


def test_check_federates_to_vikunja(trusted_email_cert_pem):
    from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc

    tls_ca = os.environ.get("TLS_CA")
    client_key = os.environ.get("TLS_CLIENT_KEY")
    if not tls_ca or not client_key:
        pytest.fail(
            "RUN_INTEGRATION=1 set but TLS_CA / TLS_CLIENT_KEY not provided "
            "(server CA PEM and mTLS client key PEM)"
        )

    channel_creds = grpc.ssl_channel_credentials(
        root_certificates=tls_ca.encode(),
        certificate_chain=trusted_email_cert_pem.encode(),
        private_key=client_key.encode(),
    )
    request = external_auth_pb2.CheckRequest()
    request.attributes.source.certificate = urllib.parse.quote(
        trusted_email_cert_pem, safe=""
    )
    request.attributes.request.http.host = "vikunja.local"
    request.attributes.request.http.path = "/api/v1"

    with grpc.secure_channel("localhost:9090", channel_creds) as channel:
        stub = external_auth_pb2_grpc.AuthorizationStub(channel)
        resp = stub.Check(request)

    # The federator minted (or reused) a Vikunja session and injected a bearer.
    assert resp.HasField("ok_response")
    added = {h.header.key: h.header.value for h in resp.ok_response.headers}
    assert added["Authorization"].startswith("Bearer ")
