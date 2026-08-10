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


def test_is_document_navigation_false_for_asset_requests():
    # Scripts/styles/images/XHR carry an asset/JSON Accept, not text/html, so a
    # non-document Sec-Fetch-Dest with that Accept is not a page load.
    for dest, accept in (
        ("script", "*/*"),
        ("style", "text/css,*/*;q=0.1"),
        ("image", "image/avif,image/webp,*/*;q=0.5"),
        ("empty", "application/json, text/plain, */*"),
    ):
        assert (
            is_document_navigation({"sec-fetch-dest": dest, "accept": accept}) is False
        )


def test_is_document_navigation_true_for_service_worker_reissued_navigation():
    # Vikunja's PWA service worker re-issues the top-level navigation to `/`
    # via fetch(event.request): Sec-Fetch-Dest drops to `empty` and
    # Sec-Fetch-Mode to `same-origin`, but the original Accept: text/html
    # survives. Must still bootstrap, or the SPA boots unauthenticated.
    assert (
        is_document_navigation(
            {
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "same-origin",
                "accept": "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8",
            }
        )
        is True
    )


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
