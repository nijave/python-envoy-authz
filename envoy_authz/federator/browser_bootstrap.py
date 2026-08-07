"""Silent front-channel login for a browser hitting a federated host directly.

The existing get_bearer ladder (session.py) authenticates API/XHR calls by
injecting `Authorization` into the *upstream* request — invisible to a
browser's own JS, so a browser SPA never becomes "logged in" from it alone.
Vikunja's frontend instead expects a real OIDC front-channel redirect (its
`/auth/openid/<provider>` route validates a `state` it stored in localStorage
before redirecting out) — but this federator's OP has no `/oauth/authorize`
(codes are minted server-to-server only, see op/routes.py). Reconciling this
without any Envoy/Contour changes: Check() detects a top-level browser
navigation and denies it with an HTTP 200 whose body is a tiny script that
does exactly what Vikunja's own "Login with <provider>" button would have
done (store `state`, then navigate to the callback route with a code we
already minted) before Vikunja's real page is ever served. Envoy sends a
`denied_response` straight to the client without proxying anything upstream,
so this never touches Vikunja.
"""

import html
import secrets
from urllib.parse import urlparse

from .providers import Provider


def is_document_navigation(headers: dict) -> bool:
    """True for a top-level browser navigation, not an API/XHR/asset request.

    `Sec-Fetch-Dest` is sent by all current Chromium/Firefox releases and is
    unambiguous (`document` only for a real address-bar/link navigation).
    Falls back to `Accept: text/html` for clients that omit Sec-Fetch-*
    (older browsers, curl, the API test suite), so those keep going through
    the existing silent get_bearer ladder rather than getting a page.
    """
    dest = headers.get("sec-fetch-dest")
    if dest is not None:
        return dest == "document"
    return "text/html" in headers.get("accept", "")


def frontend_oidc_path(provider: Provider) -> str:
    """Vikunja's own frontend OIDC-callback route (not the backend API path).

    A request here must be let through untouched: it is the page navigation
    the bootstrap script above triggers, and Vikunja's SPA (OpenIdAuth.vue)
    needs to actually render and run there.
    """
    return urlparse(provider.redirect_url).path


def render_bootstrap_html(*, redirect_path: str, code: str, state: str) -> str:
    """The whole HTTP response body for the browser-bootstrap denied_response.

    Mirrors Vikunja's frontend `redirectToProvider()` exactly (store `state`
    in localStorage, then navigate) so its callback's CSRF check passes as if
    the user had clicked its own "Login with <provider>" button. `code` and
    `state` are our own (itsdangerous URL-safe base64 / secrets.token_urlsafe)
    output and cannot contain a quote or `</script>`, but both are still
    HTML-escaped before being embedded in a JS string literal — templating
    untrusted-shaped values into a script body without escaping is exactly how
    an XSS hole gets introduced later if the value ever changes shape.
    """
    safe_code = html.escape(code, quote=True)
    safe_state = html.escape(state, quote=True)
    safe_path = html.escape(redirect_path, quote=True)
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>'
        "<script>"
        f"localStorage.setItem('state', '{safe_state}');"
        f"window.location.href = '{safe_path}?code={safe_code}&state={safe_state}';"
        "</script>"
        "</body></html>"
    )


def new_state() -> str:
    return secrets.token_urlsafe(18)
