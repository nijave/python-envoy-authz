"""RSA signing key for the OP (ported from python-client-idp/app/keys.py).

Loaded or generated on first use; persisted to disk so the JWKS / kid are
stable across restarts (Vikunja caches the discovered JWKS).
"""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc.jwk import KeySet, RSAKey

# Module-level globals wired by Task 5's init_op. Left as None here so the
# Interfaces contract is satisfied and grants.py references resolve at import
# time (they are only dereferenced at runtime, after init_op has assigned them).
key_set: KeySet | None = None
kid: str | None = None


def public_jwks_dict() -> dict:
    """The public JWKS (no private material) for the discovery /.well-known endpoint."""
    if key_set is None:
        return {"keys": []}
    return key_set.as_dict(private=False)


def load_or_create_key(path: str) -> RSAKey:
    """Load an RSA key from `path`, or generate a 2048-bit key and persist it.

    The key is unencrypted at rest, so it is created 0600 in a 0700 directory
    and an existing key with looser bits is tightened on load. Anyone who can
    read it can mint an RS256 id_token for any `sub`.
    """
    if os.path.exists(path):
        _restrict(path)
        with open(path, "rb") as handle:
            private_key = serialization.load_pem_private_key(
                handle.read(), password=None
            )
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Create with the mode already set, so the key is never briefly
        # world-readable between open() and chmod().
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
    jwk = RSAKey.import_key(private_key)
    jwk.ensure_kid()  # RFC 7638 JWK thumbprint
    return jwk


def _restrict(path: str) -> None:
    """Tighten an existing key file to 0600 if it is group/world readable."""
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        os.chmod(path, 0o600)
