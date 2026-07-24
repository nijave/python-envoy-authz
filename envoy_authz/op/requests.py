"""Starlette request adapters for authlib's OAuth2Request / JsonRequest.

authlib has no Starlette AuthorizationServer, so we adapt Starlette requests
into authlib's framework-agnostic request types ourselves. The route handlers
pre-parse the async body (form/json) and pass the parsed dict here, so the
sync authlib calls never await.
"""

from collections import defaultdict

from authlib.oauth2.rfc6749 import (
    JsonRequest,
    JsonPayload,
    OAuth2Payload,
    OAuth2Request,
)


class StarletteOAuth2Payload(OAuth2Payload):
    def __init__(self, data: dict):
        self._data = data
        self._datalist = defaultdict(list, {k: [v] for k, v in data.items()})

    @property
    def data(self):
        return self._data

    @property
    def datalist(self) -> defaultdict:
        return self._datalist


class StarletteOAuth2Request(OAuth2Request):
    def __init__(self, request, data: dict):
        super().__init__(
            method=request.method,
            uri=str(request.url),
            # Pass Starlette's case-insensitive Headers directly: authlib looks
            # up "Authorization" with a capital A, but dict(request.headers)
            # lowercases keys and would miss it.
            headers=request.headers,
        )
        self._request = request
        self._data = data
        self.payload = StarletteOAuth2Payload(data)

    @property
    def args(self):
        return dict(self._request.query_params)

    @property
    def form(self):
        return self._data


class StarletteJsonPayload(JsonPayload):
    def __init__(self, data):
        self._data = data

    @property
    def data(self):
        return self._data


class StarletteJsonRequest(JsonRequest):
    def __init__(self, request, data):
        super().__init__(request.method, str(request.url), request.headers)
        self.payload = StarletteJsonPayload(data)
