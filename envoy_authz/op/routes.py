"""OP HTTP routes (FastAPI APIRouter). Ported from app/idp/routes.py.

No /oauth/authorize route — the federator mints codes directly. Discovery still
advertises authorization_endpoint for provider-metadata compatibility.
"""

from urllib.parse import parse_qs

from fastapi import APIRouter, Request

from . import keys, runtime
from . import server as op_server

router = APIRouter()


@router.get("/.well-known/openid-configuration")
async def discovery():
    issuer = runtime.issuer()
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
    }


@router.get("/jwks.json")
async def jwks():
    return keys.public_jwks_dict()


def _parse_form(body: bytes) -> dict:
    """Parse an application/x-www-form-urlencoded body into a flat dict.

    OAuth2 token requests are always form-urlencoded; parsing the raw body
    directly avoids the python-multipart dependency Starlette's
    ``request.form()`` requires.
    """
    parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


@router.post("/oauth/token")
async def issue_token(request: Request):
    body = await request.body()
    data = _parse_form(body)
    return op_server.server.create_token_response((request, data))


@router.api_route("/oauth/userinfo", methods=["GET", "POST"])
async def userinfo(request: Request):
    if request.method == "POST":
        try:
            data = await request.json()
        except ValueError:
            data = {}
    else:
        data = dict(request.query_params)
    return op_server.server.create_endpoint_response("userinfo", (request, data))
