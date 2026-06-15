"""Session-key handshake helpers for secure entity connections."""

from __future__ import annotations

from collections.abc import Buffer
from dataclasses import dataclass

from .auth_messages import NONCE_SIZE
from .crypto import symmetric_decrypt_authenticate, symmetric_encrypt_authenticate
from .exceptions import SecureHandshakeError, SerializationError
from .keys import SessionKey


HANDSHAKE_NONCE_PRESENT = 0x01
HANDSHAKE_REPLY_NONCE_PRESENT = 0x02
HANDSHAKE_DH_PARAM_PRESENT = 0x04
HANDSHAKE_FIXED_SIZE = 1 + (NONCE_SIZE * 2)


@dataclass(frozen=True)
class HandshakePayload:
    nonce: bytes | None = None
    reply_nonce: bytes | None = None
    diffie_hellman_param: bytes | None = None


def serialize_handshake_payload(payload: HandshakePayload) -> bytes:
    """Serialize a cleartext handshake payload before session-key encryption."""

    if (
        payload.nonce is None
        and payload.reply_nonce is None
        and payload.diffie_hellman_param is None
    ):
        raise SerializationError("Handshake payload must include at least one field")

    indicator = 0
    output = bytearray(HANDSHAKE_FIXED_SIZE)

    if payload.nonce is not None:
        _require_nonce(payload.nonce, "nonce")
        indicator |= HANDSHAKE_NONCE_PRESENT
        output[1 : 1 + NONCE_SIZE] = payload.nonce

    if payload.reply_nonce is not None:
        _require_nonce(payload.reply_nonce, "reply_nonce")
        indicator |= HANDSHAKE_REPLY_NONCE_PRESENT
        start = 1 + NONCE_SIZE
        output[start : start + NONCE_SIZE] = payload.reply_nonce

    if payload.diffie_hellman_param is not None:
        indicator |= HANDSHAKE_DH_PARAM_PRESENT
        output.extend(payload.diffie_hellman_param)

    output[0] = indicator
    return bytes(output)


def parse_handshake_payload(data: Buffer) -> HandshakePayload:
    """Parse a cleartext decrypted handshake payload."""

    view = memoryview(data)
    if len(view) < 1:
        raise SerializationError("Handshake payload is empty")

    indicator = view[0]
    if indicator == 0:
        raise SerializationError("Handshake payload does not include any fields")

    nonce = None
    reply_nonce = None
    diffie_hellman_param = None

    if indicator & HANDSHAKE_NONCE_PRESENT:
        _require_available(view, 1, NONCE_SIZE, "nonce")
        nonce = bytes(view[1 : 1 + NONCE_SIZE])

    if indicator & HANDSHAKE_REPLY_NONCE_PRESENT:
        start = 1 + NONCE_SIZE
        _require_available(view, start, NONCE_SIZE, "reply_nonce")
        reply_nonce = bytes(view[start : start + NONCE_SIZE])

    if indicator & HANDSHAKE_DH_PARAM_PRESENT:
        if len(view) <= HANDSHAKE_FIXED_SIZE:
            raise SerializationError("Handshake payload is missing Diffie-Hellman bytes")
        diffie_hellman_param = bytes(view[HANDSHAKE_FIXED_SIZE:])

    return HandshakePayload(
        nonce=nonce,
        reply_nonce=reply_nonce,
        diffie_hellman_param=diffie_hellman_param,
    )


def build_handshake_1(
    key: SessionKey,
    client_nonce: bytes,
) -> bytes:
    """Build encrypted SKEY_HANDSHAKE_1 payload."""

    plaintext = serialize_handshake_payload(HandshakePayload(nonce=client_nonce))
    encrypted = _encrypt_handshake_payload(key, plaintext)
    return key.id + encrypted


def verify_handshake_2_and_build_handshake_3(
    key: SessionKey,
    encrypted_handshake_2: bytes,
    client_nonce: bytes,
) -> tuple[bytes, bytes]:
    """Verify SKEY_HANDSHAKE_2 and return ``(server_nonce, handshake3_payload)``."""

    _require_nonce(client_nonce, "client_nonce")
    plaintext = _decrypt_handshake_payload(key, encrypted_handshake_2)
    payload = parse_handshake_payload(plaintext)

    if payload.reply_nonce != client_nonce:
        raise SecureHandshakeError("Handshake 2 reply nonce did not match client nonce")
    if payload.nonce is None:
        raise SecureHandshakeError("Handshake 2 is missing server nonce")

    response_plaintext = serialize_handshake_payload(
        HandshakePayload(reply_nonce=payload.nonce)
    )
    return payload.nonce, _encrypt_handshake_payload(key, response_plaintext)


def _encrypt_handshake_payload(key: SessionKey, plaintext: bytes) -> bytes:
    return symmetric_encrypt_authenticate(
        plaintext,
        key.cipher_key,
        key.mac_key,
        key.encryption_mode,
        key.hmac_enabled,
    )


def _decrypt_handshake_payload(key: SessionKey, encrypted: bytes) -> bytes:
    return symmetric_decrypt_authenticate(
        encrypted,
        key.cipher_key,
        key.mac_key,
        key.encryption_mode,
        key.hmac_enabled,
    )


def _require_nonce(value: bytes, field_name: str) -> None:
    if len(value) != NONCE_SIZE:
        raise SerializationError(f"{field_name} must be {NONCE_SIZE} bytes")


def _require_available(
    view: memoryview, start: int, size: int, field_name: str
) -> None:
    if start + size > len(view):
        raise SerializationError(f"Handshake payload is missing {field_name}")
