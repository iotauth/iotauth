"""High-level secure client API for IoTAuth Python entities."""

from __future__ import annotations

from typing import Any

from .context import IoTAuthContext
from .keys import SessionKey
from .secure_channel import SecureChannel


class SecureClient:
    """Convenience wrapper for the client-side secure connection workflow."""

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
        self.channel: SecureChannel | None = None

    def connect(self) -> SecureChannel:
        key = self.key
        if key is None:
            keys = self.ctx.request_session_keys(
                purpose=self.purpose,
                timeout=self.timeout,
            )
            key = keys[0]
            self.key = key

        self.channel = self.ctx.connect_secure(
            key=key,
            host=self.host,
            port=self.port,
            timeout=self.timeout,
        )
        return self.channel

    def __enter__(self) -> SecureClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.channel is not None:
            self.channel.close()
