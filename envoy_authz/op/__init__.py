"""OIDC Provider package."""

from . import keys


def init_op(app, key_path: str, federation) -> None:
    """Bind OP config + signing key, init the AuthorizationServer, and mount the
    OP router on the FastAPI app.

    `federation` is a `config.FederationSettings`. Binding the issuer and the
    auth-code signer once here is what lets the request paths avoid rebuilding
    `Settings()` (and re-reading `.env`) per call.
    """
    from ..federator import store
    from . import runtime
    from .server import init_server
    from .routes import router

    runtime.configure(federation.idp_issuer)
    store.configure(federation.secret_key, federation.code_ttl_seconds)

    jwk = keys.load_or_create_key(key_path)
    keys.set_key(jwk)
    init_server(keys.key_set, keys.kid)
    app.include_router(router)
