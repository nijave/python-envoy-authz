import datetime
import logging
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto

logger = logging.getLogger(__name__)


@dataclass
class Config:
    frigate_proxy_secret: str
    # Shared across the gRPC thread pool; must not be mutated after the
    # server starts (concurrent reads during cert verification are safe).
    ha_ca_store: crypto.X509Store


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
    return Config(
        frigate_proxy_secret=os.environ["FRIGATE_X_PROXY_SECRET"],
        ha_ca_store=build_store(
            os.environ["HA_CA_CERTIFICATE"],
            os.environ.get("HA_CRL"),
        ),
    )


def verify_client_cert(
    cert_pem: str, store: crypto.X509Store
) -> x509.Certificate | None:
    """
    Verify a client certificate against the CA + CRL and require the clientAuth
    EKU. Returns the verified certificate, or None on any failure.
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
