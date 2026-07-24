import datetime
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Validated, env-driven configuration.

    Env-var names are derived from field names (FRIGATE_X_PROXY_SECRET, etc.)
    so the existing k8s manifest keeps working. Secrets are SecretStr so they
    never leak in repr/logs.
    """

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    # --- existing (preserved) ---
    frigate_x_proxy_secret: SecretStr
    ha_ca_certificate: str  # PEM
    ha_crl: str | None = None  # PEM

    # --- OP / federator (opt-in) ---
    # Federation is OFF unless all three of idp_issuer, secret_key and
    # providers_file are supplied. This keeps the pre-federation deployment
    # (the k8s manifest, which sets only the two vars above) starting and
    # behaving exactly as it did: mTLS allow gate + Frigate proxy secret, no OP
    # mounted and no federator wired. See `Settings.federation`.
    idp_issuer: str | None = None
    secret_key: SecretStr | None = None
    providers_file: str | None = None
    code_ttl_seconds: int = 10
    op_key_path: str = "op_key.pem"  # OP RSA signing key (load-or-create)

    # --- transport (moved from __main__ module constants) ---
    grpc_port: int = 5000
    http_port: int = 5001
    tls_cert_path: str = "/var/lib/tls/tls.crt"
    tls_key_path: str = "/var/lib/tls/tls.key"

    def federation(self) -> "FederationSettings | None":
        """The federation config, or None when federation is not configured.

        All three fields are required together: without `providers_file` there
        is no backend to federate to, without `secret_key` we cannot sign auth
        codes, and without `idp_issuer` the OP cannot advertise discovery.
        Returning a narrowed object means callers do ONE None check instead of
        three, and cannot half-enable federation.
        """
        if not (self.idp_issuer and self.secret_key and self.providers_file):
            return None
        return FederationSettings(
            idp_issuer=self.idp_issuer,
            secret_key=self.secret_key.get_secret_value(),
            providers_file=self.providers_file,
            code_ttl_seconds=self.code_ttl_seconds,
        )


@dataclass(frozen=True)
class FederationSettings:
    """The federation subset of `Settings`, with the optional fields resolved."""

    idp_issuer: str
    secret_key: str
    providers_file: str
    code_ttl_seconds: int


@dataclass
class Config:
    """Runtime container: validated settings plus constructed state.

    `ha_ca_store` is built from `settings` at startup (runtime state, not
    config). `frigate_proxy_secret` is exposed as a plain str for the existing
    gRPC servicer, which reads it off `Config` directly.
    """

    settings: Settings
    ha_ca_store: crypto.X509Store

    @property
    def frigate_proxy_secret(self) -> str:
        return self.settings.frigate_x_proxy_secret.get_secret_value()


def configure_crl(store: crypto.X509Store, crl_pem: str) -> bool:
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    if crl.next_update_utc <= datetime.datetime.now(datetime.timezone.utc):
        logger.warning("CRL is expired (next_update=%s), skipping", crl.next_update_utc)
        return False
    store.add_crl(crl)
    store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
    logger.info("CRL loaded (next_update=%s)", crl.next_update_utc)
    return True


def build_store(ca_cert_pem: str, crl_pem: str | None = None) -> crypto.X509Store:
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem.encode())
    store = crypto.X509Store()
    store.add_cert(ca_cert)
    if crl_pem:
        configure_crl(store, crl_pem)
    return store


def load_config() -> Config:
    settings = Settings()
    return Config(
        settings=settings,
        ha_ca_store=build_store(settings.ha_ca_certificate, settings.ha_crl),
    )


def verify_client_cert(
    cert_pem: str, store: crypto.X509Store
) -> x509.Certificate | None:
    """Verify a client certificate against the CA + CRL and require the
    clientAuth EKU. Returns the verified certificate, or None on any failure.
    """
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())
        crypto.X509StoreContext(store, cert).verify_certificate()

        crypto_cert = cert.to_cryptography()
        eku = crypto_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
            return None

        return crypto_cert
    except Exception:
        logger.exception("Client cert verification failed")
        return None
