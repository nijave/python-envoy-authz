import pytest

from envoy_authz.federator import providers
from envoy_authz.federator.store import (
    CLIENTS,
    User,
    _reset,
    build_user_info,
    configure,
    create_authorization_code,
    load_authorization_code,
    seed,
)

VIKUNJA_YAML = """
providers:
  vikunja:
    hosts: ["vikunja.example.com"]
    client_id: "vikunja"
    client_secret: "vikunja-secret"
    redirect_url: "http://localhost:3456/auth/openid/broker"
    api_base: "http://localhost:3456"
    provider_key: "broker"
    scope: "openid profile email"
"""


def _seed(tmp_path, monkeypatch):
    p = tmp_path / "providers.yaml"
    p.write_text(VIKUNJA_YAML)
    providers.load_providers(str(p))
    configure("test-secret-key", 10)
    _reset()
    seed()


def test_seed_registers_vikunja_client(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    assert "vikunja" in CLIENTS
    v = CLIENTS["vikunja"]
    assert v.get_client_id() == "vikunja"
    assert v.check_client_secret("vikunja-secret")
    assert v.check_redirect_uri("http://localhost:3456/auth/openid/broker")
    assert v.check_response_type("code")
    assert v.check_grant_type("authorization_code")
    assert v.get_allowed_scope("openid profile email phone") == "openid profile email"


def test_client_token_endpoint_auth_methods(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    v = CLIENTS["vikunja"]
    assert v.check_endpoint_auth_method("client_secret_basic", "token")
    assert v.check_endpoint_auth_method("client_secret_post", "token")
    assert not v.check_endpoint_auth_method("none", "token")


def test_stateless_code_carries_email_and_name(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    code = create_authorization_code(
        client_id="vikunja",
        redirect_uri="http://localhost:3456/auth/openid/broker",
        scope="openid profile email",
        user_id="abc123",
        email="alice@example.com",
        name="Alice",
    )
    data = load_authorization_code(code)
    assert data is not None
    assert data["user_id"] == "abc123"
    assert data["email"] == "alice@example.com"
    assert data["name"] == "Alice"
    assert data["client_id"] == "vikunja"


def test_build_user_info_uses_sub_name_email():
    u = User(id="abc123", name="Alice", email="alice@example.com")
    info = build_user_info(u, "openid profile email")
    assert info["sub"] == "abc123"
    assert info["email"] == "alice@example.com"
    assert info["name"] == "Alice"


def test_code_is_single_use(tmp_path, monkeypatch):
    """RFC 6749 4.1.2: a code MUST NOT be redeemed twice. The signature and TTL
    alone let an observed code be replayed for the whole TTL window."""
    _seed(tmp_path, monkeypatch)
    code = create_authorization_code(
        client_id="vikunja",
        redirect_uri="http://localhost:3456/auth/openid/broker",
        scope="openid profile email",
        user_id="abc123",
    )
    assert load_authorization_code(code) is not None
    assert load_authorization_code(code) is None


def test_distinct_codes_are_independently_redeemable(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    kwargs = {
        "client_id": "vikunja",
        "redirect_uri": "http://localhost:3456/auth/openid/broker",
        "scope": "openid profile email",
        "user_id": "abc123",
    }
    a, b = create_authorization_code(**kwargs), create_authorization_code(**kwargs)
    assert a != b  # distinct jti
    assert load_authorization_code(a) is not None
    assert load_authorization_code(b) is not None


def test_build_user_info_omits_absent_claims():
    """OIDC Core 5.3.2: an absent claim SHOULD NOT be sent as null. Vikunja
    cannot provision a user from {"email": null}."""
    u = User(id="abc123", name=None, email=None)
    info = build_user_info(u, "openid profile email")
    assert info["sub"] == "abc123"
    assert "email" not in info
    assert "name" not in info


def test_check_client_secret_rejects_non_ascii_without_raising(tmp_path, monkeypatch):
    """secrets.compare_digest raises TypeError on non-ASCII str, which would
    escape authlib's OAuth2Error handling as a 500 instead of a 401."""
    _seed(tmp_path, monkeypatch)
    v = CLIENTS["vikunja"]
    assert v.check_client_secret("p\u00e4sswort") is False
    assert v.check_client_secret(None) is False


def test_signer_must_be_configured(tmp_path, monkeypatch):
    from envoy_authz.federator import store

    monkeypatch.setattr(store, "_signer", None)
    with pytest.raises(RuntimeError):
        create_authorization_code(
            client_id="vikunja",
            redirect_uri="http://localhost:3456/auth/openid/broker",
            scope="openid",
            user_id="abc123",
        )
