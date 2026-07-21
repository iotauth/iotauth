"""High-level secure server API for IoTAuth Python entities."""

from __future__ import annotations

import socket
from collections.abc import Callable
from typing import Any

from .context import IoTAuthContext
from .exceptions import AuthConnectionError, ConfigError
from .secure_channel import SecureChannel
from .transports import close_socket

ListenSocketFactory = Callable[[], Any]


class SecureServer:
    """Listen for peer connections and establish server-side secure channels.

    Args:
        ctx: Runtime context for the server entity.
        host: Local hostname or IP address. Must be supplied with ``port``.
        port: Local TCP port. Must be supplied with ``host``.
        backlog: Maximum number of pending TCP connections.
        timeout: Timeout in seconds for accepting and handshaking with a peer.

    Leaving a ``with SecureServer(...)`` block closes the listening socket.
    Call ``close()`` on each channel returned by ``serve_once()`` when the
    application finishes using that peer connection.
    """

    def __init__(
        self,
        ctx: IoTAuthContext,
        *,
        host: str | None = None,
        port: int | None = None,
        backlog: int = 5,
        timeout: float | None = 60.0,  # Make default timeout 1 min
        _socket_factory: ListenSocketFactory | None = None,
    ):
        self.ctx = ctx
        self.host = host
        self.port = port
        self.backlog = backlog
        self.timeout = timeout
        self._socket_factory = _socket_factory
        self._socket: Any | None = None

    def listen(self) -> None:
        """Bind the configured address and start listening for peer connections.

        Calling this method more than once while the server is listening has no
        effect.

        Raises:
            ConfigError: If no complete listening address is available.
            AuthConnectionError: If the socket cannot bind or listen.
        """

        if self._socket is not None:
            return
        host, port = self._resolve_bind_address()
        sock = self._create_socket()
        try:
            if self.timeout is not None and hasattr(sock, "settimeout"):
                sock.settimeout(self.timeout)
            if hasattr(sock, "setsockopt"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(self.backlog)
        except OSError as exc:
            close_socket(sock)
            raise AuthConnectionError(f"Could not listen on {host}:{port}: {exc}") from exc
        self._socket = sock

    def serve_once(self) -> SecureChannel:
        """Accept one peer and complete its secure handshake.

        Returns:
            An established channel owned by the caller.

        Raises:
            ConfigError: If the server cannot resolve a listening address.
            AuthConnectionError: If accepting or reading from the peer fails.
            SecureHandshakeError: If the peer handshake fails validation.
        """

        self.listen()
        assert self._socket is not None
        try:
            client_socket, _address = self._socket.accept()
        except OSError as exc:
            raise AuthConnectionError(f"Could not accept secure connection: {exc}") from exc
        return self.ctx.accept_secure(client_socket, timeout=self.timeout)

    def close(self) -> None:
        """Close the listening socket without closing established channels."""

        if self._socket is None:
            return
        close_socket(self._socket)
        self._socket = None

    def __enter__(self) -> SecureServer:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _resolve_bind_address(self) -> tuple[str, int]:
        if self.host is not None or self.port is not None:
            if self.host is None or self.port is None:
                raise ConfigError("host and port must be provided together")
            return self.host, self.port
        if not self.ctx.config.targets:
            raise ConfigError("No server bind target was provided or configured")
        target = self.ctx.config.targets[0]
        return target.host, target.port

    def _create_socket(self) -> Any:
        if self._socket_factory is not None:
            return self._socket_factory()
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
