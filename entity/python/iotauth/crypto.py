"""Cryptographic helpers for IoTAuth Python entities."""

from __future__ import annotations

import os
from hmac import compare_digest
from typing import Any

from .context import IoTAuthContext
from .exceptions import MessageIntegrityError, SerializationError, UnsupportedCryptoError
from .keys import DistributionKey

AES_128_KEY_SIZE = 16
AES_128_CBC_IV_SIZE = 16
AES_128_CTR_IV_SIZE = 16
AES_128_GCM_IV_SIZE = 12
AES_GCM_TAG_SIZE = 12
HMAC_SHA256_SIZE = 32


def public_encrypt(payload: bytes, public_key: Any) -> bytes:
    """Encrypt bytes with an RSA public key using OAEP.

    Args:
        payload: Plaintext bytes to encrypt.
        public_key: RSA public key from the cryptography backend.

    Returns:
        RSA-encrypted bytes.

    Raises:
        UnsupportedCryptoError: If the key type is unsupported or the payload
            is too large for direct RSA encryption.
    """

    crypto = _load_crypto_backend()
    _require_rsa_public_key(public_key, crypto)
    try:
        return public_key.encrypt(payload, _oaep_padding(crypto))
    except ValueError as exc:
        raise UnsupportedCryptoError("Payload is too large for direct RSA/OAEP encryption") from exc


def private_decrypt(ciphertext: bytes, private_key: Any) -> bytes:
    """Decrypt RSA/OAEP ciphertext with a private key.

    Args:
        ciphertext: RSA-encrypted bytes.
        private_key: RSA private key from the cryptography backend.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        UnsupportedCryptoError: If the key type is unsupported.
        MessageIntegrityError: If RSA/OAEP decryption fails.
    """

    crypto = _load_crypto_backend()
    _require_rsa_private_key(private_key, crypto)
    try:
        return private_key.decrypt(ciphertext, _oaep_padding(crypto))
    except ValueError as exc:
        raise MessageIntegrityError("RSA/OAEP decryption failed") from exc


def sign_sha256(data: bytes, private_key: Any) -> bytes:
    """Create an RSA PKCS#1 v1.5 signature using SHA-256.

    Args:
        data: Bytes to sign.
        private_key: RSA private key from the cryptography backend.

    Returns:
        Signature bytes.

    Raises:
        UnsupportedCryptoError: If the key type or backend is unsupported.
    """

    crypto = _load_crypto_backend()
    _require_rsa_private_key(private_key, crypto)
    return private_key.sign(
        data,
        crypto["padding"].PKCS1v15(),
        crypto["hashes"].SHA256(),
    )


def verify_sha256(data: bytes, signature: bytes, public_key: Any) -> None:
    """Verify an RSA PKCS#1 v1.5 SHA-256 signature.

    Args:
        data: Bytes whose signature is being verified.
        signature: Signature received with ``data``.
        public_key: RSA public key from the cryptography backend.

    Raises:
        UnsupportedCryptoError: If the key type or backend is unsupported.
        MessageIntegrityError: If signature verification fails.
    """

    crypto = _load_crypto_backend()
    _require_rsa_public_key(public_key, crypto)
    try:
        public_key.verify(
            signature,
            data,
            crypto["padding"].PKCS1v15(),
            crypto["hashes"].SHA256(),
        )
    except crypto["InvalidSignature"] as exc:
        raise MessageIntegrityError("RSA/SHA-256 signature verification failed") from exc


def encrypt_and_sign_for_auth(payload: bytes, ctx: IoTAuthContext) -> bytes:
    """Encrypt a payload for Auth and sign the resulting ciphertext.

    Args:
        payload: Plaintext Auth request payload.
        ctx: Context containing Auth's public key and the entity's private key.

    Returns:
        Encrypted payload followed by its entity signature.

    Raises:
        UnsupportedCryptoError: If RSA credentials or the backend are unsupported.
    """

    encrypted = public_encrypt(payload, ctx.auth_public_key)
    signature = sign_sha256(encrypted, ctx.entity_private_key)
    return encrypted + signature


def verify_and_decrypt_from_auth(
    signed_ciphertext: bytes, ctx: IoTAuthContext, encrypted_size: int
) -> bytes:
    """Verify an Auth signature and decrypt its RSA ciphertext.

    Args:
        signed_ciphertext: RSA ciphertext followed by Auth's signature.
        ctx: Context containing Auth's public key and the entity's private key.
        encrypted_size: Length of the RSA ciphertext prefix in bytes.

    Returns:
        Verified plaintext bytes.

    Raises:
        SerializationError: If the signed payload is structurally invalid.
        MessageIntegrityError: If signature verification or decryption fails.
        UnsupportedCryptoError: If RSA credentials or the backend are unsupported.
    """

    if encrypted_size <= 0:
        raise SerializationError("encrypted_size must be positive")
    if len(signed_ciphertext) <= encrypted_size:
        raise SerializationError("signed ciphertext is missing signature bytes")

    encrypted = signed_ciphertext[:encrypted_size]
    signature = signed_ciphertext[encrypted_size:]
    verify_sha256(encrypted, signature, ctx.auth_public_key)
    return private_decrypt(encrypted, ctx.entity_private_key)


def symmetric_encrypt_authenticate(
    plaintext: bytes,
    cipher_key: bytes,
    mac_key: bytes | None,
    encryption_mode: str,
    hmac_enabled: bool,
) -> bytes:
    """Encrypt and optionally HMAC-authenticate a symmetric payload.

    Args:
        plaintext: Bytes to protect.
        cipher_key: Sixteen-byte AES-128 key.
        mac_key: Thirty-two-byte HMAC-SHA256 key when HMAC is enabled.
        encryption_mode: ``AES_128_CBC``, ``AES_128_CTR``, or ``AES_128_GCM``.
        hmac_enabled: Whether to append an HMAC-SHA256 tag.

    Returns:
        An envelope containing the IV, ciphertext, and optional HMAC tag.

    Raises:
        UnsupportedCryptoError: If a key length or encryption mode is invalid.
    """

    crypto = _load_crypto_backend()
    _validate_cipher_key(cipher_key)
    if hmac_enabled:
        _validate_mac_key(mac_key)

    iv = os.urandom(_iv_size(encryption_mode))
    encrypted = _encrypt_aes(plaintext, cipher_key, iv, encryption_mode, crypto)
    envelope = iv + encrypted
    if hmac_enabled:
        envelope += _hmac_sha256(envelope, mac_key, crypto)
    return envelope


def symmetric_decrypt_authenticate(
    envelope: bytes,
    cipher_key: bytes,
    mac_key: bytes | None,
    encryption_mode: str,
    hmac_enabled: bool,
) -> bytes:
    """Authenticate and decrypt a symmetric envelope.

    Args:
        envelope: IV, ciphertext, and optional HMAC tag to process.
        cipher_key: Sixteen-byte AES-128 key.
        mac_key: Thirty-two-byte HMAC-SHA256 key when HMAC is enabled.
        encryption_mode: ``AES_128_CBC``, ``AES_128_CTR``, or ``AES_128_GCM``.
        hmac_enabled: Whether the envelope includes an HMAC-SHA256 tag.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        SerializationError: If the envelope is truncated.
        MessageIntegrityError: If authentication or padding verification fails.
        UnsupportedCryptoError: If a key length or encryption mode is invalid.
    """

    crypto = _load_crypto_backend()
    _validate_cipher_key(cipher_key)
    if hmac_enabled:
        _validate_mac_key(mac_key)

    iv_size = _iv_size(encryption_mode)
    if len(envelope) <= iv_size:
        raise SerializationError("Symmetric envelope is missing ciphertext")

    authenticated = envelope
    if hmac_enabled:
        if len(envelope) <= iv_size + HMAC_SHA256_SIZE:
            raise SerializationError("Symmetric envelope is missing HMAC tag")
        authenticated = envelope[:-HMAC_SHA256_SIZE]
        received_tag = envelope[-HMAC_SHA256_SIZE:]
        expected_tag = _hmac_sha256(authenticated, mac_key, crypto)
        if not compare_digest(received_tag, expected_tag):
            raise MessageIntegrityError("HMAC-SHA256 verification failed")

    iv = authenticated[:iv_size]
    encrypted = authenticated[iv_size:]
    return _decrypt_aes(encrypted, cipher_key, iv, encryption_mode, crypto)


def encrypt_request_with_distribution_key(
    payload: bytes,
    sender_name: str,
    distribution_key: DistributionKey,
    *,
    hmac_enabled: bool = False,
) -> bytes:
    """Protect an Auth request with a distribution key and sender identity.

    Args:
        payload: Plaintext Auth request payload.
        sender_name: Entity name encoded into the protected request.
        distribution_key: Symmetric distribution key used for encryption.
        hmac_enabled: Whether to append an HMAC-SHA256 tag.

    Returns:
        Sender name and encrypted payload in Auth request wire format.

    Raises:
        SerializationError: If ``sender_name`` is too long.
        UnsupportedCryptoError: If key material or encryption mode is invalid.
    """

    sender = sender_name.encode("utf-8")
    if len(sender) > 255:
        raise SerializationError("sender_name must fit in one byte")
    encrypted = symmetric_encrypt_authenticate(
        payload,
        distribution_key.cipher_key,
        distribution_key.mac_key,
        distribution_key.encryption_mode,
        hmac_enabled,
    )
    return bytes([len(sender)]) + sender + encrypted


def decrypt_request_with_distribution_key(
    protected_payload: bytes,
    distribution_key: DistributionKey,
    *,
    hmac_enabled: bool = False,
) -> tuple[str, bytes]:
    """Authenticate and decrypt a distribution-key-protected request.

    Args:
        protected_payload: Sender name and encrypted payload in wire format.
        distribution_key: Symmetric distribution key used for decryption.
        hmac_enabled: Whether the payload includes an HMAC-SHA256 tag.

    Returns:
        A ``(sender_name, plaintext)`` tuple.

    Raises:
        SerializationError: If the protected payload is malformed.
        MessageIntegrityError: If authentication or decryption fails.
        UnsupportedCryptoError: If key material or encryption mode is invalid.
    """

    if not protected_payload:
        raise SerializationError("Protected distribution-key request is empty")
    sender_length = protected_payload[0]
    sender_start = 1
    sender_end = sender_start + sender_length
    if sender_end > len(protected_payload):
        raise SerializationError("Protected request sender name is truncated")
    sender = protected_payload[sender_start:sender_end].decode("utf-8")
    encrypted = protected_payload[sender_end:]
    plaintext = symmetric_decrypt_authenticate(
        encrypted,
        distribution_key.cipher_key,
        distribution_key.mac_key,
        distribution_key.encryption_mode,
        hmac_enabled,
    )
    return sender, plaintext


def _encrypt_aes(
    plaintext: bytes, key: bytes, iv: bytes, mode: str, crypto: dict[str, Any]
) -> bytes:
    cipher = _cipher(key, iv, mode, crypto, encrypting=True)
    encryptor = cipher.encryptor()
    if mode == "AES_128_CBC":
        padder = crypto["padding_sym"].PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    if mode == "AES_128_GCM":
        return ciphertext + encryptor.tag[:AES_GCM_TAG_SIZE]
    return ciphertext


def _decrypt_aes(
    encrypted: bytes, key: bytes, iv: bytes, mode: str, crypto: dict[str, Any]
) -> bytes:
    if mode == "AES_128_GCM":
        if len(encrypted) <= AES_GCM_TAG_SIZE:
            raise SerializationError("AES-GCM envelope is missing tag")
        ciphertext = encrypted[:-AES_GCM_TAG_SIZE]
        tag = encrypted[-AES_GCM_TAG_SIZE:]
        cipher = _cipher(key, iv, mode, crypto, encrypting=False, tag=tag)
    else:
        ciphertext = encrypted
        cipher = _cipher(key, iv, mode, crypto, encrypting=False)

    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except ValueError as exc:
        raise MessageIntegrityError("AES authenticated decryption failed") from exc

    if mode == "AES_128_CBC":
        unpadder = crypto["padding_sym"].PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        except ValueError as exc:
            raise MessageIntegrityError("AES-CBC padding verification failed") from exc
    return plaintext


def _cipher(
    key: bytes,
    iv: bytes,
    mode: str,
    crypto: dict[str, Any],
    *,
    encrypting: bool,
    tag: bytes | None = None,
) -> Any:
    algorithms = crypto["algorithms"]
    modes = crypto["modes"]
    Cipher = crypto["Cipher"]

    if mode == "AES_128_CBC":
        return Cipher(algorithms.AES(key), modes.CBC(iv))
    if mode == "AES_128_CTR":
        return Cipher(algorithms.AES(key), modes.CTR(iv))
    if mode == "AES_128_GCM":
        gcm_mode = (
            modes.GCM(iv) if encrypting else modes.GCM(iv, tag, min_tag_length=AES_GCM_TAG_SIZE)
        )
        return Cipher(algorithms.AES(key), gcm_mode)
    raise UnsupportedCryptoError(f"Unsupported encryption mode: {mode}")


def _hmac_sha256(data: bytes, mac_key: bytes | None, crypto: dict[str, Any]) -> bytes:
    _validate_mac_key(mac_key)
    h = crypto["hmac"].HMAC(mac_key, crypto["hashes"].SHA256())
    h.update(data)
    return h.finalize()


def _validate_cipher_key(cipher_key: bytes) -> None:
    if len(cipher_key) != AES_128_KEY_SIZE:
        raise UnsupportedCryptoError(f"AES-128 cipher key must be {AES_128_KEY_SIZE} bytes")


def _validate_mac_key(mac_key: bytes | None) -> None:
    if mac_key is None or len(mac_key) != HMAC_SHA256_SIZE:
        raise UnsupportedCryptoError(f"HMAC-SHA256 key must be {HMAC_SHA256_SIZE} bytes")


def _iv_size(mode: str) -> int:
    if mode == "AES_128_CBC":
        return AES_128_CBC_IV_SIZE
    if mode == "AES_128_CTR":
        return AES_128_CTR_IV_SIZE
    if mode == "AES_128_GCM":
        return AES_128_GCM_IV_SIZE
    raise UnsupportedCryptoError(f"Unsupported encryption mode: {mode}")


def _oaep_padding(crypto: dict[str, Any]) -> Any:
    return crypto["padding"].OAEP(
        mgf=crypto["padding"].MGF1(algorithm=crypto["hashes"].SHA1()),
        algorithm=crypto["hashes"].SHA1(),
        label=None,
    )


def _require_rsa_public_key(public_key: Any, crypto: dict[str, Any]) -> None:
    if not isinstance(public_key, crypto["rsa"].RSAPublicKey):
        raise UnsupportedCryptoError("RSA public key is required")


def _require_rsa_private_key(private_key: Any, crypto: dict[str, Any]) -> None:
    if not isinstance(private_key, crypto["rsa"].RSAPrivateKey):
        raise UnsupportedCryptoError("RSA private key is required")


def _load_crypto_backend() -> dict[str, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, hmac
        from cryptography.hazmat.primitives import padding as padding_sym
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise UnsupportedCryptoError(
            "The cryptography package is required for IoTAuth crypto operations."
        ) from exc

    return {
        "Cipher": Cipher,
        "InvalidSignature": InvalidSignature,
        "algorithms": algorithms,
        "hashes": hashes,
        "hmac": hmac,
        "modes": modes,
        "padding": padding,
        "padding_sym": padding_sym,
        "rsa": rsa,
    }
