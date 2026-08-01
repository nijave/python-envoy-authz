from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from envoy_authz.federator.store import create_authorization_code
from envoy_authz.op import keys
from tests.conftest import OP_TEST_ISSUER


def _vikunja():
    from envoy_authz.federator.providers import get_provider

    return get_provider("vikunja")


def test_discovery_document_shape(op_client):
    resp = op_client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    issuer = OP_TEST_ISSUER
    assert body["issuer"] == issuer
    assert body["token_endpoint"] == f"{issuer}/oauth/token"
    assert body["userinfo_endpoint"] == f"{issuer}/oauth/userinfo"
    assert body["jwks_uri"] == f"{issuer}/jwks.json"
    assert body["id_token_signing_alg_values_supported"] == ["RS256"]
    assert "S256" in body["code_challenge_methods_supported"]
    assert body["subject_types_supported"] == ["public"]


def test_jwks_endpoint_exposes_signing_key(op_client):
    resp = op_client.get("/jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["keys"]) == 1
    assert body["keys"][0]["kid"] == keys.kid
    assert body["keys"][0]["kty"] == "RSA"


def _mint_code(nonce=None, code_challenge=None, code_challenge_method=None):
    code = create_authorization_code(
        client_id=_vikunja().client_id,
        redirect_uri=_vikunja().redirect_url,
        scope="openid profile email",
        user_id="abc123",
        email="alice@example.com",
        name="Alice",
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    return code


def _exchange(op_client, code, code_verifier=None):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _vikunja().redirect_url,
        "client_id": _vikunja().client_id,
        "client_secret": _vikunja().client_secret,
    }
    if code_verifier is not None:
        data["code_verifier"] = code_verifier
    return op_client.post("/oauth/token", data=data)


def test_authorization_code_flow_issues_id_token(op_client):
    code = _mint_code(nonce="n1")
    resp = _exchange(op_client, code)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "access_token" in body and "id_token" in body

    pub = keys.public_jwks_dict()["keys"][0]
    pub_ks = KeySet([RSAKey.import_key({k: pub[k] for k in ("kty", "n", "e", "kid")})])
    claims = jwt.decode(body["id_token"], pub_ks, ["RS256"]).claims
    assert claims["iss"] == OP_TEST_ISSUER
    assert claims["aud"] == [_vikunja().client_id]
    assert claims["sub"] == "abc123"
    assert claims["nonce"] == "n1"
    assert claims["email"] == "alice@example.com"


def test_userinfo_with_bearer_token(op_client):
    code = _mint_code()
    body = _exchange(op_client, code).json()
    resp = op_client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert resp.status_code == 200, resp.text
    info = resp.json()
    assert info["sub"] == "abc123"
    assert info["email"] == "alice@example.com"


def test_refresh_token_rotates(op_client):
    code = _mint_code()
    body = _exchange(op_client, code).json()
    refresh = body.get("refresh_token")
    assert refresh

    def _refresh(token):
        return op_client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": token,
                "client_id": _vikunja().client_id,
                "client_secret": _vikunja().client_secret,
            },
        )

    resp = _refresh(refresh)
    assert resp.status_code == 200, resp.text
    new_body = resp.json()
    assert "access_token" in new_body
    new_refresh = new_body.get("refresh_token")
    assert new_refresh and new_refresh != refresh

    replay = _refresh(refresh)
    assert replay.status_code >= 400
    assert "error" in replay.json()


def test_pkce_positive_verifier_matches_challenge(op_client):
    verifier = generate_token(48)
    code = _mint_code(
        code_challenge=create_s256_code_challenge(verifier),
        code_challenge_method="S256",
    )
    resp = _exchange(op_client, code, verifier)
    assert resp.status_code == 200
    assert "id_token" in resp.json()


def test_pkce_negative_wrong_verifier_rejected(op_client):
    verifier = generate_token(48)
    code = _mint_code(
        code_challenge=create_s256_code_challenge(verifier),
        code_challenge_method="S256",
    )
    wrong = generate_token(48)
    assert wrong != verifier
    resp = _exchange(op_client, code, wrong)
    assert resp.status_code >= 400
    assert resp.json().get("error") == "invalid_grant"


def test_pkce_negative_missing_verifier_rejected(op_client):
    verifier = generate_token(48)
    code = _mint_code(
        code_challenge=create_s256_code_challenge(verifier),
        code_challenge_method="S256",
    )
    resp = _exchange(op_client, code, None)
    assert resp.status_code >= 400
    assert "error" in resp.json()
