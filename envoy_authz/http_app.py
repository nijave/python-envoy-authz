"""FastAPI application factory for the in-process HTTPS server.

Decoupled from the gRPC side: the caller (``__main__``) supplies a lifespan that
owns the gRPC server. The OP router is mounted only when federation is
configured (`federation` is not None) — without it there is no issuer to
advertise and no key to sign codes with, so an unmounted OP is the correct
degradation rather than one that 500s per request.
"""

from fastapi import FastAPI


def create_app(
    lifespan=None, op_key_path: str | None = None, federation=None
) -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    if op_key_path is not None and federation is not None:
        from envoy_authz.op import init_op

        init_op(app, op_key_path, federation)

    return app
