"""IoTAuth protocol message types, frame objects, and Auth payload helpers.

This module combines message-type definitions, the IoTSP frame container, and
Auth-facing payload serializers and parsers into a single protocol module.
"""

from __future__ import annotations

import json

try:
    from collections.abc import Buffer
except ImportError:
    from typing_extensions import Buffer
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from .config import SessionConfig
from .exceptions import KeyCacheError, SerializationError
from .keys import SESSION_KEY_ID_SIZE, DistributionKey, SessionKey
from .serialization import decode_uint_be, decode_varint, encode_uint_be, encode_varint

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

AUTH_ID_SIZE = 4
NONCE_SIZE = 8
DIST_KEY_EXPIRATION_TIME_SIZE = 6
KEY_EXPIRATION_TIME_SIZE = 6
REL_VALIDITY_SIZE = 6
MAC_KEY_SIZE = 32
AES_128_KEY_SIZE = 16


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------


class MessageType(IntEnum):
    """IoTAuth protocol message identifiers used on the wire."""

    AUTH_HELLO = 0
    ENTITY_HELLO = 1
    AUTH_SESSION_KEY_REQ = 10
    AUTH_SESSION_KEY_RESP = 11
    SESSION_KEY_REQ_IN_PUB_ENC = 20
    SESSION_KEY_RESP_WITH_DIST_KEY = 21
    SESSION_KEY_REQ = 22
    SESSION_KEY_RESP = 23
    SESSION_KEY_RESP_FOR_DELEGATION = 24
    SESSION_KEY_RESP_FOR_DELEGATION_WITH_DIST_KEY = 25
    SKEY_HANDSHAKE_1 = 30
    SKEY_HANDSHAKE_2 = 31
    SKEY_HANDSHAKE_3 = 32
    SECURE_COMM_MSG = 33
    FIN_SECURE_COMM = 34
    # Messages below are not implemented in Python protocol yet.
    # SECURE_PUB = 40
    # MIGRATION_REQ_WITH_SIGN = 50
    # MIGRATION_RESP_WITH_SIGN = 51
    # MIGRATION_REQ_WITH_MAC = 52
    # MIGRATION_RESP_WITH_MAC = 53
    # ADD_READER_REQ_IN_PUB_ENC = 60
    # ADD_READER_RESP_WITH_DIST_KEY = 61
    # ADD_READER_REQ = 62
    # ADD_READER_RESP = 63
    # DELEGATED_ACCESS_REQ_IN_PUB_ENC = 70
    # DELEGATED_ACCESS_RESP_WITH_DIST_KEY = 71
    # DELEGATED_ACCESS_REQ = 72
    # DELEGATED_ACCESS_RESP = 73
    # PRIVILEGED_REQ_IN_PUB_ENC = 80
    # PRIVILEGED_RESP_WITH_DIST_KEY = 81
    # PRIVILEGED_REQ = 82
    # PRIVILEGED_RESP = 83
    AUTH_ALERT = 100


# ---------------------------------------------------------------------------
# IoTSP frame container
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IoTSPFrame:
    """One framed IoTAuth protocol message.

    Attributes:
        message_type: Protocol identifier for the payload.
        payload: Unframed message payload bytes.

    Raises:
        SerializationError: If the message type is unknown or payload is not bytes.
    """

    message_type: MessageType
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.message_type, MessageType):
            object.__setattr__(self, "message_type", message_type_from_byte(int(self.message_type)))
        if not isinstance(self.payload, bytes):
            raise SerializationError("IoTSPFrame payload must be bytes")


def message_type_from_byte(value: int) -> MessageType:
    """Convert an integer wire value into a ``MessageType``.

    Args:
        value: Integer message identifier.

    Returns:
        Matching protocol message type.

    Raises:
        SerializationError: If ``value`` is not a known message identifier.
    """

    try:
        return MessageType(value)
    except ValueError as exc:
        raise SerializationError(f"Unknown IoTAuth message type: {value}") from exc


def serialize_frame(frame: IoTSPFrame) -> bytes:
    """Serialize an IoTSP frame as type, payload length, and payload.

    Args:
        frame: Protocol frame to serialize.

    Returns:
        Complete wire-format frame bytes.
    """

    return bytes([int(frame.message_type)]) + encode_varint(len(frame.payload)) + frame.payload


def parse_frame(data: Buffer, *, allow_trailing: bool = False) -> IoTSPFrame:
    """Parse one IoTSP frame from bytes.

    Args:
        data: Bytes containing a complete frame.
        allow_trailing: Whether bytes after the frame may be ignored.

    Returns:
        Parsed protocol frame.

    Raises:
        SerializationError: If the frame is empty, truncated, unknown, or has
            disallowed trailing bytes.
    """

    view = memoryview(data)
    if len(view) < 1:
        raise SerializationError("IoTSP frame is empty")

    message_type = message_type_from_byte(view[0])
    payload_length, length_size = decode_varint(view, 1)
    payload_start = 1 + length_size
    payload_end = payload_start + payload_length

    if payload_end > len(view):
        raise SerializationError("IoTSP frame payload length exceeds available data")
    if payload_end < len(view) and not allow_trailing:
        raise SerializationError("IoTSP frame contains trailing bytes")

    return IoTSPFrame(
        message_type=message_type,
        payload=bytes(view[payload_start:payload_end]),
    )


# ---------------------------------------------------------------------------
# Auth payload dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthHelloPayload:
    """Auth identity and nonce received at the start of an Auth exchange."""

    auth_id: int
    nonce: bytes


@dataclass(frozen=True)
class AuthAlertPayload:
    """Numeric error code returned by Auth."""

    code: int


@dataclass(frozen=True)
class SessionKeyRequestPayload:
    """Cleartext fields included in a session-key request to Auth."""

    entity_nonce: bytes
    auth_nonce: bytes
    num_keys: int
    entity_name: str
    purpose: dict[str, Any] | str
    diffie_hellman_param: bytes | None = None


@dataclass(frozen=True)
class SessionKeyResponsePayload:
    """Verified session keys and metadata returned by Auth."""

    entity_nonce: bytes
    crypto_spec: dict[str, Any] | str
    session_keys: list[SessionKey]


# ---------------------------------------------------------------------------
# Payload builders and parsers
# ---------------------------------------------------------------------------


def parse_auth_hello_payload(payload: Buffer) -> AuthHelloPayload:
    """Parse an ``AUTH_HELLO`` payload.

    Args:
        payload: Auth ID followed by the Auth nonce.

    Returns:
        Parsed Auth ID and nonce.

    Raises:
        SerializationError: If the payload length is invalid.
    """

    view = memoryview(payload)
    expected_length = AUTH_ID_SIZE + NONCE_SIZE
    if len(view) != expected_length:
        raise SerializationError(
            f"AUTH_HELLO payload must be {expected_length} bytes, got {len(view)}"
        )
    return AuthHelloPayload(
        auth_id=decode_uint_be(view[:AUTH_ID_SIZE]),
        nonce=bytes(view[AUTH_ID_SIZE:expected_length]),
    )


def parse_auth_alert_payload(payload: Buffer) -> AuthAlertPayload:
    """Parse a one-byte ``AUTH_ALERT`` payload.

    Args:
        payload: Buffer containing the Auth alert code.

    Returns:
        Parsed Auth alert payload.

    Raises:
        SerializationError: If the payload is not exactly one byte.
    """

    view = memoryview(payload)
    if len(view) != 1:
        raise SerializationError(f"AUTH_ALERT payload must be 1 byte, got {len(view)}")
    return AuthAlertPayload(code=view[0])


def serialize_buffered_string(value: str) -> bytes:
    """Encode a UTF-8 string with a variable-length size prefix.

    Args:
        value: Text to encode.

    Returns:
        Size-prefixed UTF-8 bytes.
    """

    encoded = value.encode("utf-8")
    return encode_varint(len(encoded)) + encoded


def parse_buffered_string(data: Buffer, offset: int = 0) -> tuple[str, int]:
    """Decode a size-prefixed UTF-8 string.

    Args:
        data: Buffer containing the encoded string.
        offset: Index at which the size prefix begins.

    Returns:
        A ``(value, bytes_consumed)`` tuple.

    Raises:
        SerializationError: If the prefix, bytes, or UTF-8 text are invalid.
    """

    view = memoryview(data)
    length, length_size = decode_varint(view, offset)
    start = offset + length_size
    end = start + length
    if end > len(view):
        raise SerializationError("Buffered string length exceeds available data")
    try:
        value = bytes(view[start:end]).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SerializationError("Buffered string is not valid UTF-8") from exc
    return value, length_size + length


def serialize_session_key_request_payload(
    request: SessionKeyRequestPayload,
) -> bytes:
    """Serialize the cleartext portion of a session-key request.

    Args:
        request: Validated request fields to encode.

    Returns:
        Session-key request payload bytes.

    Raises:
        SerializationError: If a nonce, key count, or entity name is invalid.
    """

    _require_nonce(request.entity_nonce, "entity_nonce")
    _require_nonce(request.auth_nonce, "auth_nonce")
    if request.num_keys < 1:
        raise SerializationError("num_keys must be at least 1")
    if not request.entity_name:
        raise SerializationError("entity_name must not be empty")

    purpose = _serialize_purpose(request.purpose)
    payload = (
        request.entity_nonce
        + request.auth_nonce
        + encode_uint_be(request.num_keys, 4)
        + serialize_buffered_string(request.entity_name)
        + serialize_buffered_string(purpose)
    )
    if request.diffie_hellman_param:
        payload += request.diffie_hellman_param
    return payload


def parse_session_key_response_payload(
    payload: Buffer,
    session_config: SessionConfig,
    *,
    allow_trailing: bool = False,
) -> SessionKeyResponsePayload:
    """Parse decrypted session-key response bytes.

    Args:
        payload: Decrypted response payload from Auth.
        session_config: Settings applied to parsed session keys.
        allow_trailing: Whether unparsed bytes may remain after the key records.

    Returns:
        Parsed nonce, crypto specification, and session keys.

    Raises:
        SerializationError: If the payload or a contained key record is invalid.
    """

    view = memoryview(payload)
    offset = 0
    if len(view) < NONCE_SIZE:
        raise SerializationError("Session key response is missing entity nonce")

    entity_nonce = bytes(view[offset : offset + NONCE_SIZE])
    offset += NONCE_SIZE

    crypto_spec_string, consumed = parse_buffered_string(view, offset)
    offset += consumed
    crypto_spec: dict[str, Any] | str
    try:
        parsed = json.loads(crypto_spec_string)
        crypto_spec = parsed if isinstance(parsed, dict) else crypto_spec_string
    except json.JSONDecodeError:
        crypto_spec = crypto_spec_string

    if offset + 4 > len(view):
        raise SerializationError("Session key response is missing key count")
    session_key_count = decode_uint_be(view[offset : offset + 4])
    offset += 4

    session_keys: list[SessionKey] = []
    for _ in range(session_key_count):
        key, consumed = parse_session_key_record(view, offset, session_config)
        session_keys.append(key)
        offset += consumed

    if offset < len(view) and not allow_trailing:
        trailing = len(view) - offset
        raise SerializationError(f"Session key response contains {trailing} trailing bytes")

    return SessionKeyResponsePayload(
        entity_nonce=entity_nonce,
        crypto_spec=crypto_spec,
        session_keys=session_keys,
    )


def parse_distribution_key_record(
    data: Buffer,
    *,
    offset: int = 0,
    encryption_mode: str = "AES_128_CBC",
    allow_trailing: bool = False,
) -> DistributionKey:
    """Parse one distribution-key record.

    Args:
        data: Buffer containing a distribution-key record.
        offset: Index at which the record begins.
        encryption_mode: Encryption mode assigned to the parsed key.
        allow_trailing: Whether bytes after the record may be ignored.

    Returns:
        Parsed distribution key.

    Raises:
        SerializationError: If the record is truncated or key material is invalid.
    """

    view = memoryview(data)
    cursor = offset
    if cursor + DIST_KEY_EXPIRATION_TIME_SIZE > len(view):
        raise SerializationError("Distribution key record is missing validity")

    abs_validity = decode_uint_be(view[cursor : cursor + DIST_KEY_EXPIRATION_TIME_SIZE])
    cursor += DIST_KEY_EXPIRATION_TIME_SIZE

    cipher_key, cursor = _parse_sized_bytes(view, cursor, "distribution cipher key")
    mac_key, cursor = _parse_sized_bytes(view, cursor, "distribution MAC key")

    if cursor < len(view) and not allow_trailing:
        raise SerializationError("Distribution key record contains trailing bytes")

    try:
        return DistributionKey(
            cipher_key=cipher_key,
            mac_key=mac_key,
            abs_validity=abs_validity,
            encryption_mode=encryption_mode,
        )
    except KeyCacheError as exc:
        raise SerializationError(str(exc)) from exc


def parse_session_key_record(
    data: Buffer, offset: int, session_config: SessionConfig
) -> tuple[SessionKey, int]:
    """Parse one session-key record.

    Args:
        data: Buffer containing a session-key record.
        offset: Index at which the record begins.
        session_config: Settings assigned to the parsed key.

    Returns:
        A ``(session_key, bytes_consumed)`` tuple.

    Raises:
        SerializationError: If the record is truncated or key material is invalid.
    """

    view = memoryview(data)
    cursor = offset
    fixed_size = SESSION_KEY_ID_SIZE + KEY_EXPIRATION_TIME_SIZE + REL_VALIDITY_SIZE
    if cursor + fixed_size > len(view):
        raise SerializationError("Session key record is missing fixed fields")

    key_id = bytes(view[cursor : cursor + SESSION_KEY_ID_SIZE])
    cursor += SESSION_KEY_ID_SIZE

    abs_validity = decode_uint_be(view[cursor : cursor + KEY_EXPIRATION_TIME_SIZE])
    cursor += KEY_EXPIRATION_TIME_SIZE

    rel_validity = decode_uint_be(view[cursor : cursor + REL_VALIDITY_SIZE])
    cursor += REL_VALIDITY_SIZE

    cipher_key, cursor = _parse_sized_bytes(view, cursor, "session cipher key")
    mac_key, cursor = _parse_sized_bytes(view, cursor, "session MAC key")

    try:
        key = SessionKey(
            id=key_id,
            cipher_key=cipher_key,
            mac_key=mac_key,
            abs_validity=abs_validity,
            rel_validity=rel_validity,
            encryption_mode=session_config.encryption_mode,
            hmac_enabled=session_config.hmac_enabled,
            permanent_distribution_key=session_config.permanent_distribution_key,
        )
    except KeyCacheError as exc:
        raise SerializationError(str(exc)) from exc

    return key, cursor - offset


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _serialize_purpose(purpose: dict[str, Any] | str) -> str:
    if isinstance(purpose, str):
        return purpose
    return json.dumps(purpose, separators=(",", ":"), sort_keys=True)


def _require_nonce(value: bytes, field_name: str) -> None:
    if len(value) != NONCE_SIZE:
        raise SerializationError(f"{field_name} must be {NONCE_SIZE} bytes")


def _parse_sized_bytes(view: memoryview, offset: int, field_name: str) -> tuple[bytes, int]:
    if offset >= len(view):
        raise SerializationError(f"{field_name} size byte is missing")
    size = view[offset]
    start = offset + 1
    end = start + size
    if end > len(view):
        raise SerializationError(f"{field_name} exceeds available data")
    return bytes(view[start:end]), end
