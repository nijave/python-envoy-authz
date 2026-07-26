"""Filesystem-loaded, Pydantic-validated downstream provider config.

Ported from python-client-idp/app/providers.py. Each entry in providers.yaml
is one downstream backend the federator can federate to — the single source of
truth for that backend, driving both the OIDP client registration (store.seed)
and the federator's downstream callback call (vikunja.federate).

The per-backend *values* live here; the wire *contract* (callback path shape
and POST {code, redirect_url} -> {token}) lives in vikunja.py. `extra` holds
backend-specific config (Vikunja: session_secret, the HS256 service.secret).
"""

import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel

# ${VAR} or ${VAR:-default}. VAR is a POSIX-ish env name.
_ENV_REF = re.compile(
    r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}"
)

DEFAULT_SCOPE = "openid profile email"


class Provider(BaseModel):
    """One downstream backend the federator can federate to."""

    # Envoy request hosts this backend federates for. An ALLOWLIST: a host that
    # matches no provider is allowed through with no header rather than being
    # federated, so attaching this ext_authz to an unrelated vhost cannot
    # silently inject this backend's bearer into it.
    hosts: list[str]
    client_id: str
    client_secret: str
    redirect_url: str
    api_base: str
    provider_key: str
    scope: str = DEFAULT_SCOPE
    extra: dict[str, str] = {}


class ProvidersConfig(BaseModel):
    providers: dict[str, Provider]


# Populated at startup by load_providers; read by store.seed and vikunja.federate.
PROVIDERS: dict[str, Provider] = {}


def _resolve(text: str) -> str:
    """Resolve ${VAR} / ${VAR:-default} against the environment.

    An empty value is never treated as a legitimate injection: a set-but-empty
    variable falls back to its default, matching POSIX `${VAR:-default}` (an
    empty k8s secret value or a bare `VAR=` in compose is a missing secret, not
    a deliberate empty one). With no default, unset-or-empty is a startup error.

    To opt into an empty value, give an explicit empty default: `${VAR:-}`.
    """

    def replace(match: "re.Match[str]") -> str:
        name = match.group("name")
        value = os.environ.get(name)
        if value:
            return value
        default = match.group("default")
        if default is not None:
            return default
        raise ValueError(
            f"unset or empty environment variable in providers config: {name}"
        )

    return _ENV_REF.sub(replace, text)


def _interpolate(value):
    """Recursively resolve env references in every string leaf of a parsed doc."""
    if isinstance(value, str):
        return _resolve(value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def load_providers(path: str) -> dict[str, Provider]:
    """Load, interpolate, and validate the providers file into PROVIDERS.

    Raises FileNotFoundError if the file is missing, ValueError for an
    undefined env reference, and pydantic.ValidationError for a bad schema —
    all fatal at startup by design. The caller supplies `path` (from
    Settings.providers_file); this module does not read config itself.
    """
    data = _interpolate(yaml.safe_load(Path(path).read_text()))
    cfg = ProvidersConfig.model_validate(data)
    PROVIDERS.clear()
    PROVIDERS.update(cfg.providers)
    return PROVIDERS


def get_provider(name: str) -> Provider | None:
    return PROVIDERS.get(name)


def provider_for_host(host: str) -> Provider | None:
    """The provider that federates for `host`, or None if no provider claims it.

    Host matching is case-insensitive (Envoy may forward any case) and ignores a
    `:port` suffix on the request host.
    """
    needle = host.split(":", 1)[0].casefold()
    for provider in PROVIDERS.values():
        if any(needle == h.split(":", 1)[0].casefold() for h in provider.hosts):
            return provider
    return None
