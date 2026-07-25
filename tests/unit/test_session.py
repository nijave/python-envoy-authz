import time

import httpx
import pytest

from envoy_authz.federator.providers import get_provider
from envoy_authz.federator.session import CachedSession, SessionCache, get_bearer
from envoy_authz.federator.subject import Subject
from envoy_authz.federator.vikunja import DownstreamError, VikunjaClient, VikunjaSession


# Minimal providers config so `get_provider("vikunja")` resolves when this file
# runs in isolation. `with_session_secret` toggles `extra.session_secret`, which
# gates the incoming-bearer HS256 fast-path (spec lines 394-443): set it to the
# secret `_bearer()` signs with so the fast-path tests can verify a bearer;
# unset it so the no-secret test treats an incoming bearer as opaque.
def _providers_yaml(*, with_session_secret: bool) -> str:
    extra = (
        '    extra:\n      session_secret: "test-secret-key"\n'
        if with_session_secret
        else ""
    )
    return (
        "providers:\n"
        "  vikunja:\n"
        '    hosts: ["vikunja.test"]\n'
        '    client_id: "vikunja"\n'
        '    client_secret: "vikunja-secret"\n'
        '    redirect_url: "http://localhost:3456/auth/openid/broker"\n'
        '    api_base: "http://localhost:3456"\n'
        '    provider_key: "broker"\n'
        '    scope: "openid profile email"\n' + extra
    )


@pytest.fixture(autouse=True)
def _env_and_providers(tmp_path, monkeypatch):
    # Required Settings env vars (kept for any code path that constructs
    # Settings()). Loading providers lets StubVk/CountingVk resolve
    # `get_provider("vikunja")`; by default the provider carries a session_secret
    # so the incoming-bearer fast-path is exercised.
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("FRIGATE_X_PROXY_SECRET", "test-frigate-secret")
    monkeypatch.setenv("HA_CA_CERTIFICATE", "dummy-ca")
    monkeypatch.setenv("IDP_ISSUER", "https://idp.test")
    from envoy_authz.federator import providers

    p = tmp_path / "providers.yaml"
    p.write_text(_providers_yaml(with_session_secret=True))
    providers.load_providers(str(p))


@pytest.fixture
def cache():
    return SessionCache(margin=60.0)


def _subject(sub="abc123", email="alice@example.com", name="Alice"):
    return Subject(sub=sub, email=email, name=name)


def _bearer(exp_delta=600, user_id="1", token_type=1):
    import jwt as pyjwt

    return pyjwt.encode(
        {"id": user_id, "exp": int(time.time()) + exp_delta, "type": token_type},
        "test-secret-key",
        algorithm="HS256",
    )


def _cached(bearer="cached-tok", refresh="rt", exp_delta=300):
    return CachedSession(
        bearer=bearer,
        refresh_cookie=refresh,
        exp=time.time() + exp_delta,
        user_id="1",
    )


def test_cache_get_miss(cache):
    assert cache.get("abc123") is None


def test_cache_put_then_get(cache):
    cache.put("abc123", _cached())
    got = cache.get("abc123")
    assert got is not None and got.bearer == "cached-tok"


def test_cache_get_returns_stale_entry_ladder_enforces_freshness(cache):
    # SessionCache.get does NOT evict on exp by design: the decision ladder
    # applies the freshness/margin check itself, so a stale-but-cached entry
    # with a refresh cookie is refreshed rather than dropped and re-federated
    # (spec step 2: "cached and stale (exp near) -> refresh"). The four
    # refresh-path tests below rely on this — a past-exp cached entry is still
    # returned so the ladder can rotate it.
    cache.put("abc123", _cached(exp_delta=-1))
    got = cache.get("abc123")
    assert got is not None and got.bearer == "cached-tok"


def test_get_bearer_incoming_valid_and_fresh_returns_none(cache):
    # session_secret configured + bearer verifies + belongs to the Vikunja user
    # this subject maps to + not near-expiry -> None (allow through unchanged).
    cache.put(_subject().sub, _cached(exp_delta=300))  # establishes user_id="1"
    bearer = _bearer(exp_delta=600, user_id="1")
    vk = _stub_vikunja()
    assert get_bearer(_subject(), bearer, vk, cache) is None


def test_incoming_bearer_for_a_different_user_is_not_trusted(cache):
    """A valid signature is not enough: without binding the token's `id` to the
    mTLS-derived identity, any cert holder could present another user's bearer
    and be served as them."""
    # Stale and cookie-less, so the fall-through path is federation.
    cache.put(_subject().sub, _cached(bearer="ours", refresh=None, exp_delta=-1))
    other = _bearer(exp_delta=600, user_id="99")
    vk = _stub_vikunja(federate_session=_sess("fresh", "fresh-rt"))
    # Must NOT return None; falls through and injects our own session instead.
    assert get_bearer(_subject(), other, vk, cache) == "fresh"


def test_incoming_link_share_token_is_not_trusted(cache):
    """Vikunja signs link-share tokens with the SAME service.secret and hands
    them to anyone with a public share hash, so the type must be checked."""
    cache.put(_subject().sub, _cached(bearer="ours", refresh=None, exp_delta=-1))
    share = _bearer(exp_delta=600, user_id="1", token_type=4)  # AuthTypeLinkShare
    vk = _stub_vikunja(federate_session=_sess("fresh", "fresh-rt"))
    assert get_bearer(_subject(), share, vk, cache) == "fresh"


def test_incoming_bearer_with_no_known_mapping_is_not_trusted(cache):
    """With no established subject -> Vikunja-user mapping there is nothing to
    bind against, so the incoming bearer is not trusted."""
    bearer = _bearer(exp_delta=600, user_id="1")
    vk = _stub_vikunja(federate_session=_sess("fresh", "fresh-rt"))
    assert get_bearer(_subject(), bearer, vk, cache) == "fresh"


def test_get_bearer_incoming_near_expiry_falls_to_cache(cache):
    bearer = _bearer(exp_delta=30)  # within margin (60s)
    vk = _stub_vikunja()
    cache.put(_subject().sub, _cached(bearer="cached-tok", exp_delta=300))
    # user_id="1" matches the bearer, so only the near-expiry check rejects it.
    # Near-expiry incoming -> fall to step 2 -> cached fresh -> inject cached.
    assert get_bearer(_subject(), bearer, vk, cache) == "cached-tok"


def test_get_bearer_no_session_secret_does_not_trust_incoming(cache, tmp_path):
    # No session_secret configured -> incoming bearer is opaque -> fall to cache.
    # Reload the provider without `extra.session_secret` (the autouse fixture
    # loads one with it by default).
    from envoy_authz.federator import providers

    p = tmp_path / "no-secret.yaml"
    p.write_text(_providers_yaml(with_session_secret=False))
    providers.load_providers(str(p))
    bearer = _bearer()
    vk = _stub_vikunja()
    cache.put(_subject().sub, _cached(bearer="cached-tok", exp_delta=300))
    assert get_bearer(_subject(), bearer, vk, cache) == "cached-tok"


def test_get_bearer_cached_fresh_returns_cached_bearer(cache):
    cache.put(_subject().sub, _cached(bearer="cached-tok", exp_delta=300))
    vk = _stub_vikunja()
    assert get_bearer(_subject(), None, vk, cache) == "cached-tok"


def test_get_bearer_cached_stale_refreshes(cache):
    cache.put(_subject().sub, _cached(bearer="stale", refresh="old-rt", exp_delta=-1))
    vk = _stub_vikunja(refresh_session=_sess("rotated", "new-rt"))
    assert get_bearer(_subject(), None, vk, cache) == "rotated"
    # Cache updated with the rotated session.
    got = cache.get(_subject().sub)
    assert got.bearer == "rotated" and got.refresh_cookie == "new-rt"


def test_get_bearer_refresh_401_falls_through_to_federate(cache):
    cache.put(_subject().sub, _cached(bearer="stale", refresh="old-rt", exp_delta=-1))
    vk = _stub_vikunja(
        refresh_raises=DownstreamError("revoked", refresh_revoked=True),
        federate_session=_sess("federated", "fed-rt"),
    )
    assert get_bearer(_subject(), None, vk, cache) == "federated"
    assert cache.get(_subject().sub).refresh_cookie == "fed-rt"


def test_get_bearer_no_cache_federates(cache):
    vk = _stub_vikunja(federate_session=_sess("fresh", "fresh-rt"))
    assert get_bearer(_subject(), None, vk, cache) == "fresh"
    got = cache.get(_subject().sub)
    assert got.bearer == "fresh" and got.refresh_cookie == "fresh-rt"


def test_get_bearer_refresh_5xx_raises_retryable(cache):
    cache.put(_subject().sub, _cached(bearer="stale", refresh="old-rt", exp_delta=-1))
    vk = _stub_vikunja(refresh_raises=DownstreamError("transport", retryable=True))
    with pytest.raises(DownstreamError) as exc:
        get_bearer(_subject(), None, vk, cache)
    assert exc.value.retryable


def test_get_bearer_refresh_terminal_4xx_falls_through_to_federate(cache):
    """A terminal refresh failure means the cookie will never work again (e.g. a
    rotated service.secret). Federate instead of denying, and DROP the entry so
    the identity is not pinned retrying the same dead cookie forever."""
    cache.put(_subject().sub, _cached(bearer="stale", refresh="old-rt", exp_delta=-1))
    vk = _stub_vikunja(
        refresh_raises=DownstreamError("forbidden"),
        federate_session=_sess("fresh", "fresh-rt"),
    )
    assert get_bearer(_subject(), None, vk, cache) == "fresh"
    got = cache.get(_subject().sub)
    assert got.bearer == "fresh" and got.refresh_cookie == "fresh-rt"


def test_terminal_refresh_failure_is_not_a_permanent_deny_loop(cache):
    """Regression: the dead entry used to survive, so every later request
    repeated refresh -> 4xx -> 401 until the process restarted."""
    cache.put(_subject().sub, _cached(bearer="stale", refresh="dead-rt", exp_delta=-1))
    refresh_calls = {"n": 0}

    def _refresh(cookie):
        refresh_calls["n"] += 1
        raise DownstreamError("forbidden")

    vk = _stub_vikunja(federate_session=_sess("fresh", "fresh-rt"))
    vk.refresh = _refresh

    assert get_bearer(_subject(), None, vk, cache) == "fresh"
    # Second request must NOT retry the dead cookie; the fresh entry serves it.
    assert get_bearer(_subject(), None, vk, cache) == "fresh"
    assert refresh_calls["n"] == 1


def test_retryable_refresh_failure_keeps_the_entry(cache):
    """A transient 5xx must not discard a probably-still-good refresh cookie."""
    cache.put(_subject().sub, _cached(bearer="stale", refresh="good-rt", exp_delta=-1))
    vk = _stub_vikunja(refresh_raises=DownstreamError("transport", retryable=True))
    with pytest.raises(DownstreamError):
        get_bearer(_subject(), None, vk, cache)
    got = cache.get(_subject().sub)
    assert got is not None and got.refresh_cookie == "good-rt"


def test_concurrent_refresh_is_serialized_per_identity(cache):
    """Regression: refresh ran outside the per-identity lock, so N concurrent
    Checks each replayed the same single-use cookie and all but one cascaded
    into a full federation."""
    import threading

    cache.put(_subject().sub, _cached(bearer="stale", refresh="rt-1", exp_delta=-1))
    calls = {"refresh": 0, "federate": 0}
    barrier = threading.Barrier(4)

    def _refresh(cookie):
        calls["refresh"] += 1
        return _sess("rotated", "rt-2")

    def _federate(subject):
        calls["federate"] += 1
        return _sess("federated", "rt-f")

    vk = _stub_vikunja()
    vk.refresh, vk.federate = _refresh, _federate

    results = []

    def _worker():
        barrier.wait()
        results.append(get_bearer(_subject(), None, vk, cache))

    threads = [threading.Thread(target=_worker) for _ in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert calls["refresh"] == 1, "the single-use cookie was replayed"
    assert calls["federate"] == 0, "a refresh race cascaded into federation"
    assert results == ["rotated"] * 4


def test_get_bearer_federate_5xx_raises_retryable(cache):
    vk = _stub_vikunja(federate_raises=DownstreamError("callback 500", retryable=True))
    with pytest.raises(DownstreamError) as exc:
        get_bearer(_subject(), None, vk, cache)
    assert exc.value.retryable


def test_get_bearer_federate_4xx_raises_terminal(cache):
    vk = _stub_vikunja(federate_raises=DownstreamError("callback 403"))
    with pytest.raises(DownstreamError) as exc:
        get_bearer(_subject(), None, vk, cache)
    assert not exc.value.retryable


def test_get_bearer_concurrent_same_identity_single_federate(cache):
    # Second concurrent caller for the same key reuses the first's mint.
    call_count = {"n": 0}

    class CountingVk(VikunjaClient):
        def __init__(self):
            super().__init__(get_provider("vikunja"), httpx.Client())
            self._fed = _sess("fresh", "fresh-rt")

        def federate(self, subject):
            call_count["n"] += 1
            return self._fed

    vk = CountingVk()
    import threading

    results = []

    def run():
        results.append(get_bearer(_subject(), None, vk, cache))

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == "fresh" for r in results)
    assert call_count["n"] == 1


# --- helpers ------------------------------------------------------------


def _sess(bearer, refresh, exp_delta=600):
    return VikunjaSession(
        bearer=bearer,
        refresh_cookie=refresh,
        exp=time.time() + exp_delta,
        user_id="1",
    )


def _stub_vikunja(
    refresh_session=None,
    federate_session=None,
    refresh_raises=None,
    federate_raises=None,
):
    class StubVk(VikunjaClient):
        def __init__(self):
            super().__init__(get_provider("vikunja"), httpx.Client())

        def refresh(self, refresh_cookie):
            if refresh_raises is not None:
                raise refresh_raises
            return refresh_session or _sess("rotated", "new-rt")

        def federate(self, subject):
            if federate_raises is not None:
                raise federate_raises
            return federate_session or _sess("fresh", "fresh-rt")

    return StubVk()


def test_cache_evicts_long_expired_entries(cache):
    """Unbounded growth: one bearer + refresh cookie per distinct cert forever."""
    cache.put("ancient", _cached(exp_delta=-100_000))
    cache.put("current", _cached(exp_delta=300))
    assert cache.get("ancient") is None
    assert cache.get("current") is not None


def test_cache_is_capped(cache):
    small = SessionCache(margin=60.0, max_entries=5)
    for i in range(20):
        small.put(f"sub{i}", _cached(exp_delta=300 + i))
    assert len(small._entries) <= 5


def test_lock_table_is_bounded_by_striping(cache):
    """Locks are striped, so the lock table cannot grow with distinct subjects
    (and cannot be evicted out from under a holder)."""
    for i in range(5000):
        cache.lock(f"sub{i}")
    assert len(cache._stripes) == SessionCache._STRIPES
