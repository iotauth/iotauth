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
    crypto = _load_crypto_backend()
    _require_rsa_public_key(public_key, crypto)
    try:
        return public_key.encrypt(payload, _oaep_padding(crypto))
    except ValueError as exc:
        raise UnsupportedCryptoError(
            "Payload is too large for direct RSA/OAEP encryption"
        ) from exc


def private_decrypt(ciphertext: bytes, private_key: Any) -> bytes:
    crypto = _load_crypto_backend()
    _require_rsa_private_key(private_key, crypto)
    try:
        return private_key.decrypt(ciphertext, _oaep_padding(crypto))
    except ValueError as exc:
        raise MessageIntegrityError("RSA/OAEP decryption failed") from exc


def sign_sha256(data: bytes, private_key: Any) -> bytes:
    crypto = _load_crypto_backend()
    _require_rsa_private_key(private_key, crypto)
    return private_key.sign(
        data,
        crypto["padding"].PKCS1v15(),
        crypto["hashes"].SHA256(),
    )


def verify_sha256(data: bytes, signature: bytes, public_key: Any) -> None:
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
    encrypted = public_encrypt(payload, ctx.auth_public_key)
    signature = sign_sha256(encrypted, ctx.entity_private_key)
    return encrypted + signature


def verify_and_decrypt_from_auth(
    signed_ciphertext: bytes, ctx: IoTAuthContext, encrypted_size: int
) -> bytes:
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
            modes.GCM(iv)
            if encrypting
            else modes.GCM(iv, tag, min_tag_length=AES_GCM_TAG_SIZE)
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
        raise UnsupportedCryptoError(
            f"AES-128 cipher key must be {AES_128_KEY_SIZE} bytes"
        )


def _validate_mac_key(mac_key: bytes | None) -> None:
    if mac_key is None or len(mac_key) != HMAC_SHA256_SIZE:
        raise UnsupportedCryptoError(
            f"HMAC-SHA256 key must be {HMAC_SHA256_SIZE} bytes"
        )


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
        from cryptography.hazmat.primitives import hashes, hmac, padding as padding_sym
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
