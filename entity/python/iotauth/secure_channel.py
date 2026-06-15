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
from .exceptions import ConfigError, ExpiredKeyError, SecureHandshakeError
from .handshake import build_handshake_1, verify_handshake_2_and_build_handshake_3
from .keys import SessionKey
from .messages import IoTSPFrame, MessageType
from .transports.tcp import connect, recv_frame, send_frame


SocketFactory = Callable[[str, int, float | None], Any]
NonceFactory = Callable[[int], bytes]


@dataclass
class SecureChannel:
    socket: Any
    session_key: SessionKey
    send_sequence: int = 0
    receive_sequence: int = 0
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        close = getattr(self.socket, "close", None)
        if close is not None:
            close()
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


def session_key_is_expired(key: SessionKey, *, now_ms: int | None = None) -> bool:
    if key.abs_validity is None:
        return False
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return now_ms >= key.abs_validity


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


def _close_socket(sock: Any) -> None:
    close = getattr(sock, "close", None)
    if close is None:
        return
    try:
        close()
    except OSError:
        pass
