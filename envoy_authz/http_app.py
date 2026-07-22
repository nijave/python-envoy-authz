"""FastAPI application factory for the in-process HTTPS server.

Decoupled from the gRPC side: the caller (``__main__``) supplies a
``lifespan`` that owns the gRPC server. Routes that need shared config read
it from ``request.app.state`` (populated by that lifespan).
"""

from fastapi import FastAPI


def create_app(lifespan=None) -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app
