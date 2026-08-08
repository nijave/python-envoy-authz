"""OIDC grants (ported from python-client-idp/app/idp/grants.py).

Framework-agnostic (authlib rfc6749/oidc core). authenticate_user reconstructs
a User from the stateless code / token record — there is no USERS dict.
"""

from authlib.oauth2.rfc6749 import grants
from authlib.oidc.core import grants as oidc_grants

from ..federator.store import (
    OAuth2AuthorizationCode,
    User,
    _token_record_from_payload,
    build_user_info,
    load_authorization_code,
    load_op_refresh_token,
)
from . import keys, runtime


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ("client_secret_basic", "client_secret_post")

    # No generate_/save_authorization_code: codes are minted by the federator
    # (store.create_authorization_code) as signed, self-contained tokens; this
    # grant only redeems them at the token endpoint.

    def query_authorization_code(self, code, client):
        data = load_authorization_code(code)
        if data is None or data["client_id"] != client.client_id:
            return None
        return OAuth2AuthorizationCode(
            code=code,
            client_id=data["client_id"],
            redirect_uri=data["redirect_uri"],
            scope=data["scope"],
            user_id=data["user_id"],
            email=data.get("email"),
            name=data.get("name"),
            nonce=data.get("nonce"),
            code_challenge=data.get("code_challenge"),
            code_challenge_method=data.get("code_challenge_method"),
            auth_time=data.get("auth_time"),
        )

    def delete_authorization_code(self, authorization_code):
        # No-op: stateless codes are not stored; the short TTL bounds replay.
        pass

    def authenticate_user(self, authorization_code):
        return User(
            id=authorization_code.user_id,
            name=authorization_code.name,
            email=authorization_code.email,
        )


class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True
    TOKEN_ENDPOINT_AUTH_METHODS = ("client_secret_basic", "client_secret_post")

    def authenticate_refresh_token(self, refresh_token):
        # Stateless: verify the signature + TTL and reconstruct the record from
        # the signed payload, so a refresh minted on one replica is honored on
        # any other (no shared REFRESH_TOKENS dict).
        payload = load_op_refresh_token(refresh_token)
        if payload is None:
            return None
        return _token_record_from_payload(payload, refresh_token=refresh_token)

    def authenticate_user(self, credential):
        return User(
            id=credential.user_id,
            name=credential.name,
            email=credential.email,
        )

    def revoke_old_credential(self, refresh_token):
        # No-op: stateless refresh tokens cannot be revoked server-side (a shared
        # revocation store is exactly the per-replica state this fix removes).
        # Rotation still issues a fresh token; the old one stays valid until its
        # signed TTL — the same posture as the native-app refresh token.
        pass


class OpenIDCode(oidc_grants.OpenIDCode):
    def generate_user_info(self, user, scope):
        return build_user_info(user, scope)

    def get_client_claims(self, client):
        return {"iss": runtime.issuer()}

    def resolve_client_private_key(self, client):
        return keys.key_set

    def get_encode_header(self, client):
        header = super().get_encode_header(client)
        header["kid"] = keys.kid
        return header
