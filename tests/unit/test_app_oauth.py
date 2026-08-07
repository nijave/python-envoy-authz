"""Unit tests for the native app's OAuth authorize/token flow (app_oauth).

These cover the pure request logic: PKCE, subject binding, single-use codes,
and both grants. The Check()-level wiring (denied_response shapes) is covered in
tests/unit/test_check.py.
"""

import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse

import pytest

from envoy_authz.federator import app_oauth, store
from envoy_authz.federator.subject import Subject


@pytest.fixture(autouse=True)
def _configure_store():
    # Long TTL so a mint-then-redeem within one test never expires on timing.
    store.configure("test-secret-key", 30)


def _subject(email="nick@example.com"):
    return Subject(sub="abc123def456", email=email, name="Nick V")


def _pkce():
    verifier = "a" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def _authorize_query(challenge, redirect="vikunja-flutter://callback", state="xyz"):
    return {
        "response_type": ["code"],
        "client_id": ["vikunja-flutter"],
        "redirect_uri": [redirect],
        "code_challenge": [challenge],
        "code_challenge_method": ["S256"],
        "state": [state],
    }


def _mint_code(subject, challenge, redirect="vikunja-flutter://callback"):
    loc = app_oauth.build_authorize_location(
        _authorize_query(challenge, redirect), subject
    )
    return parse_qs(urlparse(loc).query)["code"][0]


def _token_form(code, verifier, redirect="vikunja-flutter://callback"):
    return {
        "grant_type": ["authorization_code"],
        "code": [code],
        "code_verifier": [verifier],
        "client_id": ["vikunja-flutter"],
        "redirect_uri": [redirect],
    }


class _Session:
    """Stand-in for VikunjaSession: only .bearer and .exp are read."""

    def __init__(self, bearer="vikunja.jwt.token", exp=None):
        self.bearer = bearer
        self.exp = exp if exp is not None else time.time() + 600


# --- request matching -----------------------------------------------------


def test_is_app_authorize_matches_only_the_app_client():
    assert app_oauth.is_app_authorize(
        "/oauth/authorize", {"client_id": ["vikunja-flutter"]}
    )
    # The web frontend's own client on the same path must NOT match (it goes
    # through the browser bootstrap instead).
    assert not app_oauth.is_app_authorize(
        "/oauth/authorize", {"client_id": ["vikunja"]}
    )
    assert not app_oauth.is_app_authorize("/other", {"client_id": ["vikunja-flutter"]})


def test_is_app_token_matches_only_the_app_client():
    assert app_oauth.is_app_token(
        "/api/v1/oauth/token", {"client_id": ["vikunja-flutter"]}
    )
    assert not app_oauth.is_app_token(
        "/api/v1/oauth/token", {"client_id": ["something-else"]}
    )


# --- authorize ------------------------------------------------------------


def test_authorize_returns_redirect_to_app_with_code_and_state():
    _, challenge = _pkce()
    loc = app_oauth.build_authorize_location(_authorize_query(challenge), _subject())
    parsed = urlparse(loc)
    assert f"{parsed.scheme}://{parsed.netloc}" == "vikunja-flutter://callback"
    q = parse_qs(parsed.query)
    assert q["code"][0]
    assert q["state"] == ["xyz"]


def test_authorize_rejects_a_redirect_uri_not_on_the_allowlist():
    _, challenge = _pkce()
    q = _authorize_query(challenge, redirect="https://evil.example.com/cb")
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.build_authorize_location(q, _subject())
    assert exc.value.error == "invalid_request"


def test_authorize_requires_an_s256_challenge():
    q = _authorize_query("some-challenge")
    q["code_challenge_method"] = ["plain"]
    with pytest.raises(app_oauth.AppOAuthError):
        app_oauth.build_authorize_location(q, _subject())


def test_authorize_requires_response_type_code():
    _, challenge = _pkce()
    q = _authorize_query(challenge)
    q["response_type"] = ["token"]
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.build_authorize_location(q, _subject())
    assert exc.value.error == "unsupported_response_type"


def test_authorize_rejects_a_code_challenge_with_invalid_characters():
    # RFC 7636 3.2: the challenge is base64url, so non-ASCII can never be
    # legitimate. Unvalidated it crashes compare_digest at redemption time.
    q = _authorize_query("ü" * 43)
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.build_authorize_location(q, _subject())
    assert exc.value.error == "invalid_request"


def test_authorize_rejects_a_code_challenge_of_the_wrong_length():
    q = _authorize_query("abc")
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.build_authorize_location(q, _subject())
    assert exc.value.error == "invalid_request"


def test_authorize_requires_an_email_in_the_certificate():
    _, challenge = _pkce()
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.build_authorize_location(
            _authorize_query(challenge), _subject(email=None)
        )
    assert exc.value.status == 401


# --- token: authorization_code -------------------------------------------


def test_token_authorization_code_returns_the_federated_bearer():
    subject = _subject()
    verifier, challenge = _pkce()
    code = _mint_code(subject, challenge)
    session = _Session()
    body = app_oauth.handle_token(
        _token_form(code, verifier), subject, lambda s: session
    )
    assert body["access_token"] == "vikunja.jwt.token"
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 0
    assert body["refresh_token"]


def test_token_rejects_a_wrong_pkce_verifier():
    subject = _subject()
    _, challenge = _pkce()
    code = _mint_code(subject, challenge)
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(
            _token_form(code, "the-wrong-verifier"), subject, lambda s: _Session()
        )
    assert exc.value.error == "invalid_grant"


def test_token_binds_the_code_to_the_certificate_subject():
    subject = _subject()
    verifier, challenge = _pkce()
    code = _mint_code(subject, challenge)
    other = Subject(sub="different00000000", email="x@example.com", name="X")
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(_token_form(code, verifier), other, lambda s: _Session())
    assert exc.value.status == 401


def test_token_rejects_a_redirect_uri_mismatch():
    subject = _subject()
    verifier, challenge = _pkce()
    code = _mint_code(subject, challenge)
    form = _token_form(code, verifier, redirect="vikunja-flutter://callback")
    form["redirect_uri"] = ["vikunja-flutter://different"]
    with pytest.raises(app_oauth.AppOAuthError):
        app_oauth.handle_token(form, subject, lambda s: _Session())


def test_token_code_is_single_use():
    subject = _subject()
    verifier, challenge = _pkce()
    code = _mint_code(subject, challenge)
    app_oauth.handle_token(_token_form(code, verifier), subject, lambda s: _Session())
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(
            _token_form(code, verifier), subject, lambda s: _Session()
        )
    assert exc.value.error == "invalid_grant"


def test_token_rejects_a_non_ascii_code_verifier():
    # Attacker-shaped input must yield a clean OAuth error, not a
    # UnicodeEncodeError escaping the Check RPC.
    subject = _subject()
    _, challenge = _pkce()
    code = _mint_code(subject, challenge)
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(
            _token_form(code, "ü" * 64), subject, lambda s: _Session()
        )
    assert exc.value.error == "invalid_grant"


def test_token_rejects_a_non_string_code():
    # A JSON token body can carry any type; a non-str code must not reach the
    # signer (itsdangerous raises TypeError on it).
    form = _token_form("placeholder", "a" * 64)
    form["code"] = 12345
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(form, _subject(), lambda s: _Session())
    assert exc.value.error == "invalid_request"


def test_token_rejects_a_browser_bootstrap_code():
    # Bootstrap codes share the signer with app codes; the client_id claim is
    # the only boundary between the two populations.
    subject = _subject()
    code = store.create_authorization_code(
        client_id="vikunja",
        redirect_uri="http://localhost:3456/auth/openid/broker",
        scope=store.DEFAULT_SCOPE,
        user_id=subject.sub,
        email=subject.email,
        name=subject.name,
    )
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(
            _token_form(code, "a" * 64), subject, lambda s: _Session()
        )
    assert exc.value.error == "invalid_grant"


def test_token_rejects_an_expired_authorization_code(monkeypatch):
    subject = _subject()
    verifier, challenge = _pkce()
    code = _mint_code(subject, challenge)
    monkeypatch.setattr(store, "_code_ttl_seconds", -1)
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(
            _token_form(code, verifier), subject, lambda s: _Session()
        )
    assert exc.value.error == "invalid_grant"


# --- token: refresh_token -------------------------------------------------


def test_refresh_token_returns_a_new_bearer():
    subject = _subject()
    rt = store.create_app_refresh_token(
        user_id=subject.sub, email=subject.email, name=subject.name
    )
    form = {
        "grant_type": ["refresh_token"],
        "refresh_token": [rt],
        "client_id": ["vikunja-flutter"],
    }
    body = app_oauth.handle_token(form, subject, lambda s: _Session(bearer="fresh.jwt"))
    assert body["access_token"] == "fresh.jwt"
    assert body["refresh_token"]


def test_refresh_token_is_bound_to_the_certificate_subject():
    subject = _subject()
    rt = store.create_app_refresh_token(
        user_id="someone-else", email="x@example.com", name="X"
    )
    form = {
        "grant_type": ["refresh_token"],
        "refresh_token": [rt],
        "client_id": ["vikunja-flutter"],
    }
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(form, subject, lambda s: _Session())
    assert exc.value.status == 401


def test_refresh_token_rejects_a_non_string_value():
    # A JSON token body can carry any type; a non-str refresh_token must not
    # reach the signer (itsdangerous raises TypeError on it, not BadData).
    form = {
        "grant_type": ["refresh_token"],
        "refresh_token": 12345,
        "client_id": ["vikunja-flutter"],
    }
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(form, _subject(), lambda s: _Session())
    assert exc.value.error == "invalid_request"


def test_refresh_token_rejects_an_expired_token(monkeypatch):
    subject = _subject()
    rt = store.create_app_refresh_token(
        user_id=subject.sub, email=subject.email, name=subject.name
    )
    monkeypatch.setattr(store, "_APP_REFRESH_TTL_SECONDS", -1)
    form = {
        "grant_type": ["refresh_token"],
        "refresh_token": [rt],
        "client_id": ["vikunja-flutter"],
    }
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(form, subject, lambda s: _Session())
    assert exc.value.error == "invalid_grant"


def test_unsupported_grant_type_is_rejected():
    with pytest.raises(app_oauth.AppOAuthError) as exc:
        app_oauth.handle_token(
            {"grant_type": ["password"], "client_id": ["vikunja-flutter"]},
            _subject(),
            lambda s: _Session(),
        )
    assert exc.value.error == "unsupported_grant_type"
