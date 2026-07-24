import time

import httpx
import pytest
import respx

from envoy_authz.federator.providers import get_provider
from envoy_authz.federator.subject import Subject
from envoy_authz.federator.vikunja import DownstreamError, VikunjaClient

# Minimal providers config so `get_provider("vikunja")` resolves when this file
# runs in isolation. Mirrors the YAML used by the `op_client` conftest fixture.
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


@pytest.fixture
def vikunja(tmp_path):
    # The auth-code signer is bound explicitly at startup, so this path no
    # longer needs a full valid environment.
    from envoy_authz.federator import providers, store

    p = tmp_path / "providers.yaml"
    p.write_text(OP_PROVIDERS_YAML)
    providers.load_providers(str(p))
    store.configure("test-secret-key", 10)
    return VikunjaClient(
        get_provider("vikunja"), httpx.Client(base_url="http://localhost:3456")
    )


def _subject(sub="abc123", email="alice@example.com", name="Alice"):
    return Subject(sub=sub, email=email, name=name)


def _bearer(user_id="1", exp_delta=600):
    # Vikunja access tokens are HS256 JWTs signed with service.secret. We mint a
    # real one with the test secret so the client can decode exp/id from the
    # payload (no signature verification on our own obtained token).
    import jwt as pyjwt

    payload = {
        "id": user_id,
        "exp": int(time.time()) + exp_delta,
        "type": "access",
    }
    return pyjwt.encode(payload, "test-secret-key", algorithm="HS256")


def _set_cookie_header(value="rt1", expires_comma=False):
    # The verbatim Set-Cookie extraction must survive a comma-bearing Expires.
    if expires_comma:
        return (
            f"vikunja_refresh_token={value}; Path=/api/v1/user/token/refresh; "
            f"Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly"
        )
    return f"vikunja_refresh_token={value}; Path=/api/v1/user/token/refresh; HttpOnly"


@respx.mock
def test_refresh_returns_rotated_session_from_set_cookie(vikunja):
    new_bearer = _bearer(user_id="1")
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": _set_cookie_header("rotated-rt")},
            json={"token": new_bearer},
        )
    )
    session = vikunja.refresh("old-rt")
    assert session.bearer == new_bearer
    assert session.refresh_cookie == "rotated-rt"
    assert session.exp > time.time()
    assert session.user_id == "1"


@respx.mock
def test_refresh_extracts_cookie_with_comma_bearing_expires(vikunja):
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": _set_cookie_header("rt2", expires_comma=True)},
            json={"token": _bearer()},
        )
    )
    session = vikunja.refresh("old-rt")
    # The Expires comma must not truncate the cookie value.
    assert session.refresh_cookie == "rt2"


@respx.mock
def test_refresh_401_raises_refresh_revoked(vikunja):
    # 401 means the session was revoked/expired; the ladder treats this as
    # "fall through to federation", not a deny. The client surfaces it as a
    # distinct sentinel so the ladder can branch.
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(401)
    )
    with pytest.raises(DownstreamError) as exc:
        vikunja.refresh("expired")
    assert exc.value.refresh_revoked
    assert not exc.value.retryable


@respx.mock
def test_refresh_5xx_raises_retryable(vikunja):
    # 5xx → retryable → Check denies 503.
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(503)
    )
    with pytest.raises(DownstreamError) as exc:
        vikunja.refresh("old-rt")
    assert exc.value.retryable
    assert not exc.value.refresh_revoked


@respx.mock
def test_refresh_4xx_terminal_raises_non_retryable(vikunja):
    # A terminal 4xx (not 401) → non-retryable → Check denies 401.
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        return_value=httpx.Response(403)
    )
    with pytest.raises(DownstreamError) as exc:
        vikunja.refresh("old-rt")
    assert not exc.value.retryable
    assert not exc.value.refresh_revoked


@respx.mock
def test_refresh_network_error_raises_retryable(vikunja):
    respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
        side_effect=httpx.ConnectError("boom")
    )
    with pytest.raises(DownstreamError) as exc:
        vikunja.refresh("old-rt")
    assert exc.value.retryable


@respx.mock
def test_federate_posts_code_and_redirect_url(vikunja):
    new_bearer = _bearer(user_id="1")
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": _set_cookie_header("fresh-rt")},
            json={"token": new_bearer},
        )
    )
    session = vikunja.federate(_subject())
    assert session.bearer == new_bearer
    assert session.refresh_cookie == "fresh-rt"
    # The callback body is {code, redirect_url} — NOT an id_token.
    sent = respx.calls[0].request
    import json as _json

    body = _json.loads(sent.content)
    assert "code" in body and "redirect_url" in body
    assert "id_token" not in body
    assert body["redirect_url"] == get_provider("vikunja").redirect_url


@respx.mock
def test_federate_5xx_raises_retryable(vikunja):
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(500, text="boom")
    )
    with pytest.raises(DownstreamError) as exc:
        vikunja.federate(_subject())
    assert exc.value.retryable


@respx.mock
def test_federate_4xx_raises_terminal(vikunja):
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(403)
    )
    with pytest.raises(DownstreamError) as exc:
        vikunja.federate(_subject())
    assert not exc.value.retryable


@respx.mock
def test_federate_missing_token_raises_downstream_error(vikunja):
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(200, json={})
    )
    with pytest.raises(DownstreamError):
        vikunja.federate(_subject())


@respx.mock
def test_federate_no_set_cookie_caches_with_none(vikunja):
    # Callback returns a token but no Set-Cookie → cache bearer with
    # refresh_cookie=None; a future refresh 401s → re-federate (spec line 465).
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(200, json={"token": _bearer()})
    )
    session = vikunja.federate(_subject())
    assert session.bearer
    assert session.refresh_cookie is None


def test_client_never_logs_bearer_or_cookie(vikunja, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    token = _bearer()
    with respx.mock:
        respx.post("http://localhost:3456/api/v1/user/token/refresh").mock(
            return_value=httpx.Response(
                200,
                headers={"set-cookie": _set_cookie_header("secret-rt")},
                json={"token": token},
            )
        )
        vikunja.refresh("old-rt")
    for record in caplog.records:
        msg = record.getMessage()
        assert token not in msg
        assert "secret-rt" not in msg


def test_federate_without_email_fails_fast(vikunja):
    """A cert with no rfc822Name SAN cannot provision a Vikunja user. Deny with
    a cause-naming error rather than an opaque downstream 4xx."""
    with pytest.raises(DownstreamError) as exc:
        vikunja.federate(_subject(email=None))
    assert "rfc822Name" in str(exc.value)
    assert exc.value.retryable is False


@respx.mock
def test_undecodable_bearer_raises_instead_of_caching_exp_zero(vikunja):
    """exp=0.0 would be cached as a permanently-stale entry, silently turning
    every later request into a Vikunja round-trip."""
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(200, json={"token": "not-a-jwt"})
    )
    with pytest.raises(DownstreamError):
        vikunja.federate(_subject())


@respx.mock
def test_bearer_without_exp_raises(vikunja):
    import jwt as pyjwt

    no_exp = pyjwt.encode({"id": "1"}, "test-secret-key", algorithm="HS256")
    respx.post("http://localhost:3456/api/v1/auth/openid/broker/callback").mock(
        return_value=httpx.Response(200, json={"token": no_exp})
    )
    with pytest.raises(DownstreamError):
        vikunja.federate(_subject())
