import os

from joserfc import jwt
from joserfc.jwk import RSAKey, KeySet


def test_generated_key_is_not_group_or_world_readable(tmp_path):
    """The key is unencrypted at rest and signs id_tokens for any `sub`, so it
    must never land 0644 via the default umask."""
    from envoy_authz.op.keys import load_or_create_key

    path = tmp_path / "keys" / "private.pem"
    load_or_create_key(str(path))
    assert os.stat(path).st_mode & 0o077 == 0
    assert os.stat(path.parent).st_mode & 0o077 == 0


def test_existing_loose_key_is_tightened_on_load(tmp_path):
    """An already-deployed 0644 key is repaired rather than trusted as-is."""
    from envoy_authz.op.keys import load_or_create_key

    path = tmp_path / "private.pem"
    load_or_create_key(str(path))
    os.chmod(path, 0o644)
    load_or_create_key(str(path))
    assert os.stat(path).st_mode & 0o077 == 0


def test_key_is_stable_across_loads(tmp_path):
    from envoy_authz.op.keys import load_or_create_key

    path = str(tmp_path / "private.pem")
    assert load_or_create_key(path).kid == load_or_create_key(path).kid


def test_keys_expose_kid_and_single_rsa_key(tmp_path, monkeypatch):
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", "x")
    from envoy_authz.op.keys import load_or_create_key

    jwk = load_or_create_key(str(tmp_path / "private.pem"))
    assert jwk.kid and isinstance(jwk.kid, str)
    pub = jwk.as_dict()
    entry = {k: pub[k] for k in ("kty", "n", "e", "kid")}
    entry.update({"alg": "RS256", "use": "sig"})
    assert entry["kty"] == "RSA"
    assert entry["e"] == "AQAB"


def test_id_token_roundtrip_signs_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "x")
    monkeypatch.setenv("HA_CA_CERTIFICATE", "x")
    from envoy_authz.op.keys import load_or_create_key

    jwk = load_or_create_key(str(tmp_path / "private.pem"))
    ks = KeySet([jwk])
    header = {"alg": "RS256", "kid": jwk.kid}
    claims = {
        "iss": "https://idp.test",
        "aud": ["self-client"],
        "sub": "1",
        "iat": 1700000000,
        "exp": 1700003600,
    }
    token = jwt.encode(header, claims, ks, ["RS256"])
    pub = jwk.as_dict()
    pub_ks = KeySet([RSAKey.import_key({k: pub[k] for k in ("kty", "n", "e", "kid")})])
    decoded = jwt.decode(token, pub_ks, ["RS256"])
    assert decoded.claims["sub"] == "1"
    assert decoded.claims["aud"] == ["self-client"]
