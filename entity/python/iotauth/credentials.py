"""Credential loading helpers for IoTAuth entities."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .exceptions import CredentialError


def load_auth_public_key(path: str | Path) -> Any:
    """Load Auth's RSA public key from an X.509 PEM certificate.

    The C API expects Auth's public credential path to point at an X.509
    certificate and extracts the public key from that certificate. Python follows
    that behavior first, with a fallback for raw PEM public keys for developer
    convenience.
    """

    crypto = _load_crypto_backend()
    data = _read_pem(path, "Auth public credential")

    try:
        cert = crypto["x509"].load_pem_x509_certificate(data)
        public_key = cert.public_key()
    except ValueError:
        try:
            public_key = crypto["serialization"].load_pem_public_key(data)
        except (TypeError, ValueError) as exc:
            raise CredentialError(f"Could not parse Auth public credential: {path}") from exc

    if not isinstance(public_key, crypto["rsa"].RSAPublicKey):
        raise CredentialError("Auth public key must be RSA")
    return public_key


def load_entity_private_key(path: str | Path) -> Any:
    """Load the entity's RSA private key from a PEM file."""

    crypto = _load_crypto_backend()
    data = _read_pem(path, "Entity private key")

    try:
        private_key = crypto["serialization"].load_pem_private_key(data, password=None)
    except TypeError as exc:
        raise CredentialError(
            "Encrypted private keys are not supported yet; passphrase support "
            "will be added explicitly later"
        ) from exc
    except ValueError as exc:
        raise CredentialError(f"Could not parse entity private key: {path}") from exc

    if not isinstance(private_key, crypto["rsa"].RSAPrivateKey):
        raise CredentialError("Entity private key must be RSA")
    return private_key


def _read_pem(path: str | Path, label: str) -> bytes:
    credential_path = Path(path)
    try:
        return credential_path.read_bytes()
    except OSError as exc:
        raise CredentialError(f"{label} could not be read: {credential_path}") from exc


def _load_crypto_backend() -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:
        raise CredentialError(
            "The cryptography package is required for credential loading. "
            "Install it before using IoTAuthContext with real PEM credentials."
        ) from exc

    return {
        "rsa": rsa,
        "serialization": serialization,
        "x509": x509,
    }
