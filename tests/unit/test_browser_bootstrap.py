"""Unit tests for the browser-bootstrap helpers (pure functions, no gRPC)."""

from envoy_authz.federator.browser_bootstrap import (
    frontend_oidc_path,
    is_document_navigation,
    render_bootstrap_html,
)
from envoy_authz.federator.providers import Provider


def _provider(**overrides) -> Provider:
    defaults = {
        "hosts": ["vikunja.example.com"],
        "client_id": "vikunja",
        "client_secret": "s",
        "redirect_url": "https://vikunja.example.com/auth/openid/broker",
        "api_base": "http://vikunja:3456",
        "provider_key": "broker",
    }
    defaults.update(overrides)
    return Provider(**defaults)


def test_is_document_navigation_true_for_sec_fetch_dest_document():
    assert is_document_navigation({"sec-fetch-dest": "document"}) is True


def test_is_document_navigation_false_for_sec_fetch_dest_other_values():
    # A real browser sends this for scripts/styles/images/XHR — must not be
    # treated as a page load even though the same browser is asking.
    for dest in ("script", "style", "image", "empty"):
        assert is_document_navigation({"sec-fetch-dest": dest}) is False


def test_is_document_navigation_falls_back_to_accept_header():
    # No Sec-Fetch-Dest (older browser / curl / the existing API tests) —
    # Accept: text/html is the fallback signal.
    assert is_document_navigation({"accept": "text/html,application/xhtml+xml"})
    assert not is_document_navigation({"accept": "application/json"})
    assert not is_document_navigation({})


def test_frontend_oidc_path_is_the_redirect_url_path_component():
    provider = _provider(redirect_url="https://vikunja.example.com/auth/openid/broker")
    assert frontend_oidc_path(provider) == "/auth/openid/broker"


def test_render_bootstrap_html_sets_state_before_navigating():
    body = render_bootstrap_html(
        redirect_path="/auth/openid/broker", code="a.b.c", state="xyz123"
    )
    # Order matters: Vikunja's own redirectToProvider() stores state THEN
    # navigates — reversing this would fail its CSRF check every time.
    set_state_index = body.index("localStorage.setItem('state', 'xyz123')")
    navigate_index = body.index("window.location.href")
    assert set_state_index < navigate_index
    assert "/auth/openid/broker?code=a.b.c&state=xyz123" in body


def test_render_bootstrap_html_escapes_html_special_characters():
    # code/state are our own itsdangerous/secrets output and never contain
    # these characters in practice, but the render must not silently trust
    # that — an unescaped `</script>` or quote would be a real XSS hole the
    # moment either value's shape ever changes.
    body = render_bootstrap_html(
        redirect_path="/auth/openid/broker",
        code="</script><script>alert(1)</script>",
        state="'; alert(2); '",
    )
    assert "<script>alert(1)</script>" not in body
    assert "'; alert(2); '" not in body
