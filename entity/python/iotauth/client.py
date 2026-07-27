"""High-level secure client API for IoTAuth Python entities."""

from __future__ import annotations

from typing import Any

from .context import IoTAuthContext
from .exceptions import SecureClientStateError
from .keys import SessionKey
from .secure_channel import SecureChannel


class SecureClient:
    """Establish client-side secure channels with an IoTAuth peer.

    Args:
        ctx: Runtime context for the client entity.
        key: Session key to use. When omitted, ``connect()`` requests one from
            Auth.
        purpose: Purpose override used when requesting a session key.
        host: Peer hostname or IP address. Must be supplied with ``port``.
        port: Peer TCP port. Must be supplied with ``host``.
        timeout: Timeout in seconds for Auth, connection, and handshake work.

    The client is a context manager. Leaving its ``with`` block closes the
    channel returned by ``connect()``. Send and receive application data through
    that channel rather than through ``SecureClient``. A client owns at most one
    active channel at a time.
    """

    def __init__(
        self,
        ctx: IoTAuthContext,
        *,
        key: SessionKey | None = None,
        purpose: dict[str, object] | str | None = None,
        host: str | None = None,
        port: int | None = None,
        timeout: float | None = 5.0,
    ):
        self.ctx = ctx
        self.key = key
        self.purpose = purpose
        self.host = host
        self.port = port
        self.timeout = timeout
        self._channel: SecureChannel | None = None

    def connect(self) -> SecureChannel:
        """Request a key when needed and establish a secure channel.

        Returns:
            The channel to use for sending, receiving, and explicit closure.

        Raises:
            ConfigError: If no key purpose or complete peer address is available.
            AuthConnectionError: If Auth or the peer cannot be reached.
            AuthProtocolError: If Auth returns an unexpected response.
            ExpiredKeyError: If the selected key has expired.
            SecureClientStateError: If this client already owns an open channel.
            SecureHandshakeError: If the peer handshake fails validation.
        """

        if self._channel is not None:
            if not self._channel.closed:
                raise SecureClientStateError("SecureClient already owns an open channel")
            self._channel = None

        key = self.key
        if key is None:
            keys = self.ctx.request_session_keys(
                purpose=self.purpose,
                timeout=self.timeout,
            )
            key = keys[0]
            self.key = key

        channel = self.ctx.connect_secure(
            key=key,
            host=self.host,
            port=self.port,
            timeout=self.timeout,
        )
        self._channel = channel
        return channel

    def __enter__(self) -> SecureClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        channel = self._channel
        self._channel = None
        if channel is not None:
            channel.close()
