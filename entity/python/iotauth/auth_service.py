"""Auth-facing workflows for IoTAuth Python entities."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from typing import Any

from .context import IoTAuthContext
from .crypto import (
    encrypt_and_sign_for_auth,
    encrypt_request_with_distribution_key,
    symmetric_decrypt_authenticate,
    verify_and_decrypt_from_auth,
)
from .exceptions import AuthConnectionError, AuthProtocolError, ConfigError, SerializationError
from .keys import DistributionKey, SessionKey
from .protocol import (
    NONCE_SIZE,
    IoTSPFrame,
    MessageType,
    SessionKeyRequestPayload,
    parse_auth_alert_payload,
    parse_auth_hello_payload,
    parse_distribution_key_record,
    parse_session_key_response_payload,
    serialize_session_key_request_payload,
)
from .transports import close_socket, connect, recv_frame, send_frame

AUTH_ALERT_MESSAGES = {
    0: "invalid distribution key",
    1: "invalid session key request",
    2: "unknown internal error",
}

SocketFactory = Callable[[str, int, float | None], Any]
NonceFactory = Callable[[int], bytes]


def request_session_keys(
    ctx: IoTAuthContext,
    *,
    purpose: dict[str, object] | str | None = None,
    count: int | None = None,
    timeout: float | None = 5.0,
    _socket_factory: SocketFactory | None = None,
    _nonce_factory: NonceFactory = secrets.token_bytes,
) -> list[SessionKey]:
    """Request session keys from Auth over TCP and store them in ``ctx``."""

    request_purpose = _select_purpose(ctx, purpose)
    request_count = ctx.config.num_keys if count is None else count
    if request_count < 1:
        raise ConfigError("session key request count must be at least 1")

    sock = _open_auth_socket(ctx, timeout=timeout, socket_factory=_socket_factory)
    try:
        hello_frame = recv_frame(sock)
        hello = _parse_expected_auth_hello(ctx, hello_frame)
        entity_nonce = _nonce_factory(NONCE_SIZE)
        if len(entity_nonce) != NONCE_SIZE:
            raise AuthProtocolError(f"entity nonce factory must return {NONCE_SIZE} bytes")

        request_payload = serialize_session_key_request_payload(
            SessionKeyRequestPayload(
                entity_nonce=entity_nonce,
                auth_nonce=hello.nonce,
                num_keys=request_count,
                entity_name=ctx.config.entity.name,
                purpose=request_purpose,
            )
        )
        protected_payload, message_type = _protect_session_key_request(ctx, request_payload)
        send_frame(sock, IoTSPFrame(message_type, protected_payload))

        response_frame = recv_frame(sock)
        return _handle_session_key_response(ctx, response_frame, entity_nonce)
    finally:
        close_socket(sock)


def distribution_key_is_expired(key: DistributionKey, *, now_ms: int | None = None) -> bool:
    """Return true when a distribution key's absolute validity has passed."""

    if key.abs_validity is None:
        return False
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return now_ms >= key.abs_validity


def _open_auth_socket(
    ctx: IoTAuthContext,
    *,
    timeout: float | None,
    socket_factory: SocketFactory | None,
) -> Any:
    if socket_factory is None:
        return connect(ctx.config.auth.host, ctx.config.auth.port, timeout=timeout)
    try:
        sock = socket_factory(ctx.config.auth.host, ctx.config.auth.port, timeout)
    except OSError as exc:
        raise AuthConnectionError(f"Could not connect to Auth: {exc}") from exc
    if timeout is not None and hasattr(sock, "settimeout"):
        sock.settimeout(timeout)
    return sock


def _select_purpose(
    ctx: IoTAuthContext, purpose: dict[str, object] | str | None
) -> dict[str, object] | str:
    if purpose is not None:
        return purpose
    if not ctx.config.purposes:
        raise ConfigError("No session key purpose was provided or configured")
    return ctx.config.purposes[0]


def _parse_expected_auth_hello(ctx: IoTAuthContext, frame: IoTSPFrame) -> Any:
    if frame.message_type == MessageType.AUTH_ALERT:
        _raise_auth_alert(frame.payload)
    if frame.message_type != MessageType.AUTH_HELLO:
        raise AuthProtocolError(f"Expected AUTH_HELLO, received {frame.message_type.name}")
    hello = parse_auth_hello_payload(frame.payload)
    if hello.auth_id != ctx.config.auth.id:
        raise AuthProtocolError(
            f"Auth ID mismatch: expected {ctx.config.auth.id}, got {hello.auth_id}"
        )
    return hello


def _protect_session_key_request(ctx: IoTAuthContext, payload: bytes) -> tuple[bytes, MessageType]:
    if ctx.distribution_key is None or distribution_key_is_expired(ctx.distribution_key):
        return encrypt_and_sign_for_auth(payload, ctx), MessageType.SESSION_KEY_REQ_IN_PUB_ENC

    return (
        encrypt_request_with_distribution_key(
            payload,
            ctx.config.entity.name,
            ctx.distribution_key,
        ),
        MessageType.SESSION_KEY_REQ,
    )


def _handle_session_key_response(
    ctx: IoTAuthContext, frame: IoTSPFrame, entity_nonce: bytes
) -> list[SessionKey]:
    if frame.message_type == MessageType.AUTH_ALERT:
        _raise_auth_alert(frame.payload)
    if frame.message_type == MessageType.SESSION_KEY_RESP_WITH_DIST_KEY:
        plaintext = _decrypt_response_with_new_distribution_key(ctx, frame.payload)
    elif frame.message_type == MessageType.SESSION_KEY_RESP:
        plaintext = _decrypt_response_with_existing_distribution_key(ctx, frame.payload)
    else:
        raise AuthProtocolError(
            "Expected SESSION_KEY_RESP_WITH_DIST_KEY or SESSION_KEY_RESP, "
            f"received {frame.message_type.name}"
        )

    response = parse_session_key_response_payload(
        plaintext, ctx.config.session, allow_trailing=True
    )
    if response.entity_nonce != entity_nonce:
        raise AuthProtocolError("Auth response nonce did not match entity nonce")

    for key in response.session_keys:
        ctx.session_keys.add(key, replace=True)
    return response.session_keys


def _decrypt_response_with_new_distribution_key(ctx: IoTAuthContext, payload: bytes) -> bytes:
    encrypted_size = _rsa_key_size_bytes(ctx.entity_private_key)
    signed_dist_key_size = encrypted_size * 2
    if len(payload) <= signed_dist_key_size:
        raise SerializationError("SESSION_KEY_RESP_WITH_DIST_KEY is missing encrypted session keys")

    distribution_record = verify_and_decrypt_from_auth(
        payload[:signed_dist_key_size], ctx, encrypted_size
    )
    distribution_key = parse_distribution_key_record(
        distribution_record,
        encryption_mode=ctx.config.session.distribution_encryption_mode,
    )
    ctx.distribution_key = distribution_key
    return symmetric_decrypt_authenticate(
        payload[signed_dist_key_size:],
        distribution_key.cipher_key,
        distribution_key.mac_key,
        ctx.config.session.encryption_mode,
        distribution_key.mac_key is not None,
    )


def _decrypt_response_with_existing_distribution_key(ctx: IoTAuthContext, payload: bytes) -> bytes:
    if ctx.distribution_key is None:
        raise AuthProtocolError("Received SESSION_KEY_RESP but no distribution key is available")
    return symmetric_decrypt_authenticate(
        payload,
        ctx.distribution_key.cipher_key,
        ctx.distribution_key.mac_key,
        ctx.config.session.encryption_mode,
        ctx.distribution_key.mac_key is not None,
    )


def _raise_auth_alert(payload: bytes) -> None:
    alert = parse_auth_alert_payload(payload)
    message = AUTH_ALERT_MESSAGES.get(alert.code, "unknown Auth alert")
    raise AuthProtocolError(f"Auth returned alert {alert.code}: {message}")


def _rsa_key_size_bytes(key: Any) -> int:
    key_size = getattr(key, "key_size", None)
    if key_size is None:
        raise SerializationError("RSA key size is unavailable")
    return key_size // 8
