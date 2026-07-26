import pytest
from pydantic import ValidationError

from envoy_authz.federator import providers

VIKUNJA_YAML = """
providers:
  vikunja:
    hosts: ["vikunja.example.com"]
    client_id: "vikunja"
    client_secret: "vikunja-secret"
    redirect_url: "http://localhost:3456/auth/openid/broker"
    api_base: "http://localhost:3456"
    provider_key: "broker"
    scope: "openid profile email"
    extra:
      session_secret: "hs256-shared-secret"
"""


def _write(tmp_path, text):
    path = tmp_path / "providers.yaml"
    path.write_text(text)
    return str(path)


def test_load_providers_parses_entry(tmp_path):
    loaded = providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    vikunja = loaded["vikunja"]
    assert vikunja.client_id == "vikunja"
    assert vikunja.client_secret == "vikunja-secret"
    assert vikunja.redirect_url == "http://localhost:3456/auth/openid/broker"
    assert vikunja.api_base == "http://localhost:3456"
    assert vikunja.provider_key == "broker"
    assert vikunja.scope == "openid profile email"
    assert vikunja.extra == {"session_secret": "hs256-shared-secret"}


def test_scope_defaults_when_omitted(tmp_path):
    text = """
providers:
  acme:
    hosts: ["acme.example.com"]
    client_id: "acme"
    client_secret: "s"
    redirect_url: "http://acme/cb"
    api_base: "http://acme"
    provider_key: "broker"
"""
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["acme"].scope == "openid profile email"


def test_extra_defaults_to_empty_dict(tmp_path):
    loaded = providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    # session_secret present in this fixture; verify the default via acme:
    text = """
providers:
  acme:
    hosts: ["acme.example.com"]
    client_id: "acme"
    client_secret: "s"
    redirect_url: "http://acme/cb"
    api_base: "http://acme"
    provider_key: "broker"
"""
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["acme"].extra == {}


def test_hosts_allowlist_lookup(tmp_path):
    providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    assert providers.provider_for_host("vikunja.example.com").client_id == "vikunja"
    # Case-insensitive, and a :port suffix on the request host is ignored.
    assert providers.provider_for_host("VIKUNJA.Example.COM") is not None
    assert providers.provider_for_host("vikunja.example.com:8443") is not None


def test_unlisted_host_matches_no_provider(tmp_path):
    """A host no provider claims must NOT federate (allowlist, not denylist)."""
    providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    assert providers.provider_for_host("home-assistant.example.com") is None
    assert providers.provider_for_host("") is None


def test_provider_requires_hosts(tmp_path):
    text = """
providers:
  nohosts:
    client_id: "x"
    client_secret: "s"
    redirect_url: "http://x/cb"
    api_base: "http://x"
    provider_key: "broker"
"""
    with pytest.raises(ValidationError):
        providers.load_providers(_write(tmp_path, text))


def test_load_populates_module_globals_and_getter(tmp_path):
    providers.load_providers(_write(tmp_path, VIKUNJA_YAML))
    assert "vikunja" in providers.PROVIDERS
    assert providers.get_provider("vikunja").client_id == "vikunja"
    assert providers.get_provider("nope") is None


def test_env_interpolation_uses_default_when_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("VIKUNJA_API_BASE", raising=False)
    text = VIKUNJA_YAML.replace(
        '"http://localhost:3456"', '"${VIKUNJA_API_BASE:-http://localhost:3456}"'
    )
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["vikunja"].api_base == "http://localhost:3456"


def test_env_interpolation_prefers_env_over_default(tmp_path, monkeypatch):
    monkeypatch.setenv("VIKUNJA_API_BASE", "http://vikunja:3456")
    text = VIKUNJA_YAML.replace(
        '"http://localhost:3456"', '"${VIKUNJA_API_BASE:-http://localhost:3456}"'
    )
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["vikunja"].api_base == "http://vikunja:3456"


def test_env_interpolation_empty_var_falls_back_to_default(tmp_path, monkeypatch):
    """A set-but-EMPTY var is a missing injection, not a deliberate empty value."""
    monkeypatch.setenv("VIKUNJA_API_BASE", "")
    text = VIKUNJA_YAML.replace(
        '"http://localhost:3456"', '"${VIKUNJA_API_BASE:-http://localhost:3456}"'
    )
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["vikunja"].api_base == "http://localhost:3456"


def test_empty_env_var_without_default_raises(tmp_path, monkeypatch):
    """An empty secret must fail startup rather than register as ""."""
    monkeypatch.setenv("VIKUNJA_CLIENT_SECRET", "")
    text = VIKUNJA_YAML.replace('"vikunja-secret"', '"${VIKUNJA_CLIENT_SECRET}"')
    with pytest.raises(ValueError):
        providers.load_providers(_write(tmp_path, text))


def test_explicit_empty_default_opts_into_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("VIKUNJA_SESSION_SECRET", raising=False)
    text = VIKUNJA_YAML.replace(
        '"hs256-shared-secret"', '"${VIKUNJA_SESSION_SECRET:-}"'
    )
    loaded = providers.load_providers(_write(tmp_path, text))
    assert loaded["vikunja"].extra["session_secret"] == ""


def test_undefined_env_var_without_default_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    text = VIKUNJA_YAML.replace('"vikunja-secret"', '"${MISSING_VAR}"')
    with pytest.raises(ValueError):
        providers.load_providers(_write(tmp_path, text))


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        providers.load_providers(str(tmp_path / "does-not-exist.yaml"))


def test_invalid_schema_raises(tmp_path):
    text = """
providers:
  broken:
    client_id: "broken"
"""
    with pytest.raises(ValidationError):
        providers.load_providers(_write(tmp_path, text))
