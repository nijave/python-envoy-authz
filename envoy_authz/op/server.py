"""Starlette AuthorizationServer glue (no authlib Starlette AS integration).

Subclasses authlib's framework-agnostic base AuthorizationServer and implements
the adapter methods the Flask integration would have provided. Also subclasses
UserInfoEndpoint to use the base ResourceProtector.validate_request (authlib's
acquire_token is Flask-only).
"""

from authlib._joserfc_helpers import import_any_key
from authlib.common.security import generate_token
from authlib.consts import default_json_headers
from authlib.oauth2.rfc6749 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenGenerator, BearerTokenValidator
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import UserInfoEndpoint

from ..federator.store import build_user_info, query_client, query_token, save_token
from . import runtime
from .grants import AuthorizationCodeGrant, OpenIDCode, RefreshTokenGrant
from .requests import StarletteJsonRequest, StarletteOAuth2Request


class InMemoryBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return query_token(token_string)


class StarletteUserInfoEndpoint(UserInfoEndpoint):
    """UserInfoEndpoint whose __call__ uses the framework-agnostic
    ResourceProtector.validate_request (authlib's acquire_token is Flask-only).
    """

    def generate_user_info(self, user, scope):
        return build_user_info(user, scope)

    def get_issuer(self) -> str:
        return runtime.issuer()

    def __call__(self, request):
        token = self.resource_protector.validate_request(["openid"], request)
        client = token.get_client()
        user = token.get_user()
        user_info = self.generate_user_info(user, token.scope)
        # Signed userinfo (userinfo_signed_response_alg) is YAGNI for Vikunja.
        if client is not None and client.client_metadata.get(
            "userinfo_signed_response_alg"
        ):
            user_info["iss"] = self.get_issuer()
            user_info["aud"] = client.client_id
            from joserfc import jwt as _jwt

            key = import_any_key(self.resolve_private_key())
            data = _jwt.encode({"alg": "RS256"}, user_info, key, ["RS256"])
            return 200, data, [("Content-Type", "application/jwt")]
        return 200, user_info, default_json_headers


require_oauth = ResourceProtector()


class StarletteAuthorizationServer(_AuthorizationServer):
    def __init__(self, query_client, save_token):
        super().__init__()
        self._query_client = query_client
        self._save_token = save_token

    def query_client(self, client_id):
        return self._query_client(client_id)

    def save_token(self, token, request):
        return self._save_token(token, request)

    def create_oauth2_request(self, request):
        # `request` is a (starlette_request, parsed_data) carrier from the route.
        starlette_req, data = request
        return StarletteOAuth2Request(starlette_req, data)

    def create_json_request(self, request):
        starlette_req, data = request
        return StarletteJsonRequest(starlette_req, data)

    def handle_response(self, status, payload, headers):
        from starlette.responses import JSONResponse, Response

        # authlib passes headers as a list of (name, value) tuples; Starlette
        # responses want a dict (or Mapping with .items()).
        if isinstance(headers, list):
            headers = dict(headers)
        if isinstance(payload, dict):
            return JSONResponse(content=payload, status_code=status, headers=headers)
        return Response(content=payload, status_code=status, headers=headers)

    def send_signal(self, name, *args, **kwargs):
        pass

    def get_error_uri(self, request, error):
        return None


# Constructed lazily by init_server (needs keys). Route modules import `server`.
server: StarletteAuthorizationServer | None = None


def init_server(key_set, kid) -> StarletteAuthorizationServer:
    """Bind keys, register grants + the userinfo endpoint, wire the token
    generator, and register the bearer validator."""
    global server
    server = StarletteAuthorizationServer(
        query_client=query_client, save_token=save_token
    )
    server.register_token_generator(
        "default",
        BearerTokenGenerator(
            lambda *a, **k: generate_token(42),  # access token
            lambda *a, **k: generate_token(48),  # refresh token
        ),
    )
    server.register_grant(
        AuthorizationCodeGrant,
        [CodeChallenge(required=False), OpenIDCode(require_nonce=False)],
    )
    server.register_grant(RefreshTokenGrant)
    require_oauth.register_token_validator(InMemoryBearerTokenValidator())
    server.register_endpoint(
        StarletteUserInfoEndpoint(server=server, resource_protector=require_oauth)
    )
    return server
