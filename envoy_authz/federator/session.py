"""Per-identity session cache and the get_bearer federation decision ladder.

get_bearer (spec lines 389–443) decides, for an incoming Envoy request, whether
to allow the client's own bearer through unchanged (return None), inject a
cached/refreshed/federated bearer upstream (return str), or deny (raise
DownstreamError; the caller catches and denies). The hot path never calls
Vikunja — it uses local exp checks; only refresh/federation reach Vikunja.
Secrets are never logged.
"""

import logging
import threading
import time

from pydantic import BaseModel

from .subject import Subject
from .vikunja import DownstreamError, VikunjaClient

logger = logging.getLogger(__name__)


class CachedSession(BaseModel):
    bearer: str
    refresh_cookie: str | None = None
    exp: float = 0.0
    user_id: str | None = None


class SessionCache:
    """Thread-safe in-memory cache keyed by stable subject `sub`.

    Per-key locking serializes the cold paths (refresh AND federation) for one
    identity, so a burst of concurrent Checks for the same user neither
    double-federates nor races on Vikunja's single-use refresh cookie.

    Bounded: an entry is dropped once it is `retain` seconds past its `exp`, and
    the table is capped at `max_entries` (oldest-expiry first). Without this,
    every distinct client cert ever seen retained a bearer + refresh cookie for
    the life of the process.

    Locks are STRIPED (a fixed-size array indexed by hash of the key) rather
    than one lock per key. A per-key lock table would either grow without bound
    or, if evicted, could be removed while a thread held it — handing a second
    thread a fresh lock for the same key and silently breaking the mutual
    exclusion the cold path depends on. Two unrelated subjects occasionally
    sharing a stripe only costs a little serialization on the cold path.
    """

    _STRIPES = 256

    def __init__(
        self,
        margin: float = 60.0,
        retain: float = 3600.0,
        max_entries: int = 10_000,
    ):
        self.margin = margin
        self._retain = retain
        self._max_entries = max_entries
        self._entries: dict[str, CachedSession] = {}
        self._stripes = [threading.Lock() for _ in range(self._STRIPES)]
        self._guard = threading.Lock()

    def get(self, key: str) -> CachedSession | None:
        return self._entries.get(key)

    def put(self, key: str, session: CachedSession) -> None:
        with self._guard:
            self._entries[key] = session
            self._evict_locked()

    def drop(self, key: str) -> None:
        """Forget an entry. Used when its refresh cookie is known to be dead,
        so the identity falls back to federation instead of retrying forever."""
        with self._guard:
            self._entries.pop(key, None)

    def lock(self, key: str) -> threading.Lock:
        return self._stripes[hash(key) % self._STRIPES]

    def _evict_locked(self) -> None:
        """Drop long-expired entries, then cap the table. Caller holds _guard."""
        cutoff = _now() - self._retain
        for key in [k for k, e in self._entries.items() if e.exp < cutoff]:
            del self._entries[key]
        overflow = len(self._entries) - self._max_entries
        if overflow > 0:
            stalest = sorted(self._entries, key=lambda k: self._entries[k].exp)
            for key in stalest[:overflow]:
                del self._entries[key]

    def clear(self) -> None:
        with self._guard:
            self._entries.clear()


def _now() -> float:
    return time.time()


# Vikunja's AuthTypeUser. Vikunja signs OTHER token types with the same
# service.secret — notably link-share tokens (AuthTypeLinkShare), which are
# handed out to anyone holding a public share hash. A valid signature therefore
# does NOT imply "a user token", so the type is checked explicitly.
_VIKUNJA_AUTH_TYPE_USER = 1


def _verify_incoming_bearer(
    bearer: str, session_secret: str | None, expect_user_id: str | None
) -> tuple[bool, float]:
    """Local HS256 fast-path (spec lines 394-398, 435-443). Returns
    (trusted, exp). `session_secret` is the provider's Vikunja service.secret
    (HS256). When it is unset/empty we return (False, 0) — we never trust an
    incoming client bearer we cannot verify (spec: "without Vikunja's HS256
    secret we cannot verify an incoming client bearer, so we never trust it").
    This is distinct from the cached session, whose `exp` we decode without a
    signature check (it came over our trusted channel).

    A valid signature alone is NOT sufficient. The token must also be a user
    token AND belong to `expect_user_id` — the Vikunja user this mTLS identity
    is known to map to. Otherwise any cert holder could present a bearer minted
    for a DIFFERENT user (or an unauthenticated link-share token) and be passed
    straight through as them, which would make the mTLS identity — the entire
    point of this gate — irrelevant on this branch.

    `expect_user_id` is None when we have no established mapping for this
    subject yet; there is then nothing to bind against, so we do not trust the
    incoming bearer and fall through to the cache/federate path.
    """
    if not session_secret or not expect_user_id:
        return False, 0.0
    import jwt as pyjwt
    from jwt import InvalidTokenError

    try:
        payload = pyjwt.decode(bearer, session_secret, algorithms=["HS256"])
    except InvalidTokenError:
        return False, 0.0
    except Exception:
        logger.exception("incoming-bearer decode failed unexpectedly")
        return False, 0.0
    if payload.get("type") != _VIKUNJA_AUTH_TYPE_USER:
        logger.info("incoming-bearer rejected: not a user token")
        return False, 0.0
    if str(payload.get("id")) != str(expect_user_id):
        logger.warning("incoming-bearer rejected: belongs to a different user")
        return False, 0.0
    return True, float(payload.get("exp") or 0.0)


def get_bearer(
    subject: Subject,
    incoming_bearer: str | None,
    vikunja: VikunjaClient,
    cache: SessionCache,
) -> str | None:
    """Decision ladder. Returns str (inject upstream), None (allow client's
    bearer through unchanged), or raises DownstreamError (deny). The raised
    DownstreamError's `retryable` flag tells Check which HTTP status to deny
    with: retryable (Vikunja unreachable / 5xx) → 503; terminal (4xx) → 401."""
    key = subject.sub
    now = _now()

    # The provider's Vikunja service.secret (HS256), used to verify an incoming
    # client bearer locally. Unset → we never trust an incoming bearer.
    session_secret = vikunja.session_secret

    # 1. Incoming bearer present? Only trusted if it verifies AND belongs to the
    # Vikunja user this mTLS subject already maps to (see _verify_incoming_bearer).
    if incoming_bearer:
        known = cache.get(key)
        valid, exp = _verify_incoming_bearer(
            incoming_bearer, session_secret, known.user_id if known else None
        )
        if valid and exp > now + cache.margin:
            logger.info("allowed-through-client-bearer sub=%s", key)
            return None  # client's token is fine; no injection
        # unbound, wrong user, near-expiry, or unverifiable → fall to step 2

    # 2. Cached and fresh? (fast path, no lock — dict reads are atomic)
    cached = cache.get(key)
    if cached is not None and cached.exp > now + cache.margin:
        logger.info("injected-cached sub=%s", key)
        return cached.bearer

    # 3/4. Cold path: refresh or federate, serialized per identity. The lock
    # covers BOTH so concurrent Checks for one identity cannot each replay the
    # same single-use refresh cookie (Vikunja rotates it, so the losers would
    # 401 and each cascade into a full federation).
    return _renew(key, subject, vikunja, cache)


def _cache_session(key: str, session, cache: SessionCache) -> None:
    cache.put(
        key,
        CachedSession(
            bearer=session.bearer,
            refresh_cookie=session.refresh_cookie,
            exp=session.exp,
            user_id=session.user_id,
        ),
    )


def _renew(
    key: str, subject: Subject, vikunja: VikunjaClient, cache: SessionCache
) -> str:
    """Refresh if we hold a usable cookie, else federate — under the per-key
    lock, re-checking the cache first so a concurrent caller reuses the winner's
    session instead of minting its own."""
    with cache.lock(key):
        cached = cache.get(key)
        if cached is not None and cached.exp > _now() + cache.margin:
            return cached.bearer

        if cached is not None and cached.refresh_cookie:
            try:
                session = vikunja.refresh(cached.refresh_cookie)
            except DownstreamError as exc:
                if exc.retryable:
                    # Transient (unreachable / 5xx). Keep the entry — its cookie
                    # is probably still good — and let Check deny 503 so the
                    # client retries rather than burning a federation.
                    logger.warning("refresh-unavailable sub=%s", key)
                    raise
                # Revoked, or any other terminal failure (e.g. a rotated
                # service.secret): this cookie will never work again. Drop the
                # entry and federate, instead of retrying it forever.
                logger.info("refresh-dead sub=%s, federating", key)
                cache.drop(key)
            else:
                _cache_session(key, session, cache)
                logger.info("injected-refreshed sub=%s", key)
                return session.bearer

        try:
            session = vikunja.federate(subject)
        except DownstreamError:
            logger.warning("federation-failure sub=%s", key)
            raise
        _cache_session(key, session, cache)
        logger.info("injected-federated sub=%s", key)
        return session.bearer
