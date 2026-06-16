"""Secure channel setup for IoTAuth Python entities."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .auth_messages import NONCE_SIZE
from .config import TargetServer
from .context import IoTAuthContext
from .crypto import symmetric_decrypt_authenticate, symmetric_encrypt_authenticate
from .exceptions import (
    AuthConnectionError,
    ConfigError,
    ExpiredKeyError,
    InvalidSequenceNumberError,
    KeyCacheError,
    SecureChannelClosed,
    SecureHandshakeError,
    SerializationError,
)
from .handshake import (
    build_handshake_1,
    parse_handshake_1_key_id,
    verify_handshake_1_and_build_handshake_2,
    verify_handshake_2_and_build_handshake_3,
    verify_handshake_3,
)
from .keys import SessionKey
from .messages import IoTSPFrame, MessageType
from .serialization import decode_uint_be, encode_uint_be
from .transports.tcp import connect, recv_frame, send_frame


SocketFactory = Callable[[str, int, float | None], Any]
NonceFactory = Callable[[int], bytes]
SEQ_NUM_SIZE = 8
MAX_SEQUENCE_NUMBER = (1 << (SEQ_NUM_SIZE * 8)) - 1


@dataclass
class SecureChannel:
    socket: Any
    session_key: SessionKey
    send_sequence: int = 0
    receive_sequence: int = 0
    closed: bool = False

    def send(self, data: bytes) -> None:
        _ensure_channel_open(self)
        _check_session_key_validity(self.session_key)
        payload = _coerce_payload(data)
        encrypted = _encrypt_secure_message(self, payload)
        send_frame(self.socket, IoTSPFrame(MessageType.SECURE_COMM_MSG, encrypted))
        self.send_sequence += 1

    def recv(self) -> bytes:
        _ensure_channel_open(self)
        try:
            frame = recv_frame(self.socket)
        except AuthConnectionError as exc:
            if "closed" in str(exc).lower():
                self.close()
                raise SecureChannelClosed(
                    "Secure channel closed while receiving"
                ) from exc
            raise
        if frame.message_type != MessageType.SECURE_COMM_MSG:
            raise SerializationError(
                f"Expected SECURE_COMM_MSG, received {frame.message_type.name}"
            )

        payload = _decrypt_secure_message(self, frame.payload)
        _check_session_key_validity(self.session_key)
        self.receive_sequence += 1
        return payload

    def close(self) -> None:
        if self.closed:
            return
        close = getattr(self.socket, "close", None)
        if close is not None:
            try:
                close()
            except OSError:
                pass
        self.closed = True


def connect_secure(
    ctx: IoTAuthContext,
    *,
    key: SessionKey,
    host: str | None = None,
    port: int | None = None,
    target: TargetServer | None = None,
    timeout: float | None = 5.0,
    _socket_factory: SocketFactory | None = None,
    _nonce_factory: NonceFactory = secrets.token_bytes,
) -> SecureChannel:
    """Open a TCP connection and complete the client-side secure handshake."""

    _check_session_key_validity(key)
    resolved_host, resolved_port = _resolve_target(ctx, host=host, port=port, target=target)
    sock = _open_socket(
        resolved_host,
        resolved_port,
        timeout=timeout,
        socket_factory=_socket_factory,
    )
    try:
        client_nonce = _nonce_factory(NONCE_SIZE)
        if len(client_nonce) != NONCE_SIZE:
            raise SecureHandshakeError(
                f"client nonce factory must return {NONCE_SIZE} bytes"
            )

        handshake_1 = build_handshake_1(key, client_nonce)
        send_frame(sock, IoTSPFrame(MessageType.SKEY_HANDSHAKE_1, handshake_1))

        response = recv_frame(sock)
        if response.message_type != MessageType.SKEY_HANDSHAKE_2:
            raise SecureHandshakeError(
                f"Expected SKEY_HANDSHAKE_2, received {response.message_type.name}"
            )

        _, handshake_3 = verify_handshake_2_and_build_handshake_3(
            key,
            response.payload,
            client_nonce,
        )
        send_frame(sock, IoTSPFrame(MessageType.SKEY_HANDSHAKE_3, handshake_3))
        _check_session_key_validity(key)
        return SecureChannel(socket=sock, session_key=key)
    except Exception:
        _close_socket(sock)
        raise


def accept_secure(
    ctx: IoTAuthContext,
    sock: Any,
    *,
    timeout: float | None = 5.0,
    _nonce_factory: NonceFactory = secrets.token_bytes,
) -> SecureChannel:
    """Complete the server-side secure handshake on an accepted TCP socket."""

    if timeout is not None and hasattr(sock, "settimeout"):
        sock.settimeout(timeout)
    try:
        handshake_1 = recv_frame(sock)
        if handshake_1.message_type != MessageType.SKEY_HANDSHAKE_1:
            raise SecureHandshakeError(
                f"Expected SKEY_HANDSHAKE_1, received {handshake_1.message_type.name}"
            )

        key_id = parse_handshake_1_key_id(handshake_1.payload)
        key = _lookup_session_key(ctx, key_id)
        _check_session_key_validity(key)

        server_nonce = _nonce_factory(NONCE_SIZE)
        if len(server_nonce) != NONCE_SIZE:
            raise SecureHandshakeError(
                f"server nonce factory must return {NONCE_SIZE} bytes"
            )

        _, handshake_2_payload = verify_handshake_1_and_build_handshake_2(
            key,
            handshake_1.payload,
            server_nonce,
        )
        send_frame(sock, IoTSPFrame(MessageType.SKEY_HANDSHAKE_2, handshake_2_payload))

        handshake_3 = recv_frame(sock)
        if handshake_3.message_type != MessageType.SKEY_HANDSHAKE_3:
            raise SecureHandshakeError(
                f"Expected SKEY_HANDSHAKE_3, received {handshake_3.message_type.name}"
            )
        verify_handshake_3(key, handshake_3.payload, server_nonce)
        _check_session_key_validity(key)
        return SecureChannel(socket=sock, session_key=key)
    except Exception:
        _close_socket(sock)
        raise


def session_key_is_expired(key: SessionKey, *, now_ms: int | None = None) -> bool:
    if key.abs_validity is None:
        return False
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return now_ms >= key.abs_validity


def _serialize_secure_message(sequence: int, data: bytes) -> bytes:
    if sequence > MAX_SEQUENCE_NUMBER:
        raise InvalidSequenceNumberError("Secure message sequence number overflow")
    return encode_uint_be(sequence, SEQ_NUM_SIZE) + data


def _parse_secure_message(plaintext: bytes) -> tuple[int, bytes]:
    if len(plaintext) < SEQ_NUM_SIZE:
        raise SerializationError("Secure message is missing sequence number")
    sequence = decode_uint_be(plaintext[:SEQ_NUM_SIZE])
    return sequence, plaintext[SEQ_NUM_SIZE:]


def _encrypt_secure_message(channel: SecureChannel, data: bytes) -> bytes:
    plaintext = _serialize_secure_message(channel.send_sequence, data)
    return symmetric_encrypt_authenticate(
        plaintext,
        channel.session_key.cipher_key,
        channel.session_key.mac_key,
        channel.session_key.encryption_mode,
        channel.session_key.hmac_enabled,
    )


def _decrypt_secure_message(channel: SecureChannel, encrypted: bytes) -> bytes:
    plaintext = symmetric_decrypt_authenticate(
        encrypted,
        channel.session_key.cipher_key,
        channel.session_key.mac_key,
        channel.session_key.encryption_mode,
        channel.session_key.hmac_enabled,
    )
    sequence, payload = _parse_secure_message(plaintext)
    if sequence != channel.receive_sequence:
        raise InvalidSequenceNumberError(
            "Secure message sequence number mismatch: "
            f"expected {channel.receive_sequence}, got {sequence}"
        )
    return payload


def _resolve_target(
    ctx: IoTAuthContext,
    *,
    host: str | None,
    port: int | None,
    target: TargetServer | None,
) -> tuple[str, int]:
    if target is not None:
        if host is not None or port is not None:
            raise ConfigError("target cannot be combined with host or port")
        return target.host, target.port
    if host is not None or port is not None:
        if host is None or port is None:
            raise ConfigError("host and port must be provided together")
        return host, port
    if not ctx.config.targets:
        raise ConfigError("No target server was provided or configured")
    configured = ctx.config.targets[0]
    return configured.host, configured.port


def _open_socket(
    host: str,
    port: int,
    *,
    timeout: float | None,
    socket_factory: SocketFactory | None,
) -> Any:
    if socket_factory is None:
        return connect(host, port, timeout=timeout)
    sock = socket_factory(host, port, timeout)
    if timeout is not None and hasattr(sock, "settimeout"):
        sock.settimeout(timeout)
    return sock


def _check_session_key_validity(key: SessionKey) -> None:
    if session_key_is_expired(key):
        raise ExpiredKeyError(f"Session key is expired: {key.id.hex()}")


def _ensure_channel_open(channel: SecureChannel) -> None:
    if channel.closed:
        raise SecureChannelClosed("Secure channel is closed")


def _coerce_payload(data: bytes) -> bytes:
    try:
        return bytes(data)
    except TypeError as exc:
        raise SerializationError("SecureChannel payload must be bytes-like") from exc


def _lookup_session_key(ctx: IoTAuthContext, key_id: bytes) -> SessionKey:
    try:
        return ctx.session_keys.require(key_id)
    except KeyCacheError as exc:
        raise SecureHandshakeError(
            f"Session key not found for handshake: {key_id.hex()}"
        ) from exc


def _close_socket(sock: Any) -> None:
    close = getattr(sock, "close", None)
    if close is None:
        return
    try:
        close()
    except OSError:
        pass
