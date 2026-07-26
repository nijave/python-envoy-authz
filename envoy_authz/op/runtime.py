"""OP configuration resolved once at startup.

Pairs with `keys` (which holds the signing key the same way): grants and routes
read the issuer from here instead of constructing a fresh `Settings()` per
request, which re-scanned the environment and re-parsed `.env` from disk on
every token, discovery and userinfo call.
"""

_issuer: str = ""


def configure(issuer: str) -> None:
    """Bind the OP issuer. Called once at startup by `init_op`."""
    global _issuer
    _issuer = issuer


def issuer() -> str:
    if not _issuer:
        raise RuntimeError("OP issuer is not configured; call op.runtime.configure()")
    return _issuer
