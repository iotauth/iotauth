"""Runtime context for IoTAuth Python entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import EntityConfig, load_config
from .credentials import (
    load_auth_public_key,
    load_entity_private_key,
    load_permanent_distribution_key,
)
from .exceptions import CredentialError
from .keys import DistributionKey, SessionKey, SessionKeyCache

if TYPE_CHECKING:
    from .secure_channel import SecureChannel


@dataclass
class IoTAuthContext:
    """Runtime configuration, credentials, and session-key state for an entity.

    Attributes:
        config: Parsed entity configuration.
        auth_public_key: Auth's RSA public key, or ``None`` in permanent
            distribution-key mode.
        entity_private_key: The entity's RSA private key, or ``None`` in
            permanent distribution-key mode.
        distribution_key: Distribution key used to protect Auth requests.
        session_keys: In-memory cache populated by session-key requests.

    Note:
        Private credentials, distribution keys, and cached session keys are
        excluded from the object representation to avoid exposing secrets.
    """

    config: EntityConfig
    auth_public_key: Any
    entity_private_key: Any = field(repr=False)
    distribution_key: DistributionKey | None = field(repr=False)
    session_keys: SessionKeyCache = field(repr=False)

    @classmethod
    def from_config(cls, path: str | Path, *, validate_paths: bool = True) -> IoTAuthContext:
        """Create a runtime context from an entity configuration file.

        Args:
            path: Path to a JSON or dotted-properties entity configuration.
            validate_paths: Whether configured credential and key files must
                exist during parsing.

        Returns:
            An initialized context with an empty session-key cache.

        Raises:
            ConfigError: If the configuration is missing, malformed, or invalid.
            CredentialError: If configured credentials or permanent key
                material cannot be loaded.
        """

        config = load_config(path, validate_paths=validate_paths)
        return cls.from_entity_config(config)

    @classmethod
    def from_entity_config(cls, config: EntityConfig) -> IoTAuthContext:
        """Create a runtime context from parsed entity configuration.

        Args:
            config: Validated entity configuration.

        Returns:
            A context containing RSA credentials for normal mode or a loaded
            symmetric distribution key for permanent distribution-key mode.

        Raises:
            CredentialError: If required credential paths or permanent key
                material are missing or unreadable.
        """

        if config.session.permanent_distribution_key:
            distribution_key = load_permanent_distribution_key(config)
            auth_public_key = None
            entity_private_key = None
        else:
            if config.auth.public_key_path is None or config.entity.private_key_path is None:
                raise CredentialError(
                    "RSA credential paths are required when permanent distribution key mode is off"
                )
            distribution_key = None
            auth_public_key = load_auth_public_key(config.auth.public_key_path)
            entity_private_key = load_entity_private_key(config.entity.private_key_path)

        return cls(
            config=config,
            auth_public_key=auth_public_key,
            entity_private_key=entity_private_key,
            distribution_key=distribution_key,
            session_keys=SessionKeyCache(),
        )

    def request_session_keys(
        self,
        *,
        purpose: dict[str, object] | str | None = None,
        count: int | None = None,
        timeout: float | None = 5.0,
    ) -> list[SessionKey]:
        """Request session keys from Auth and store them in the cache.

        Args:
            purpose: Override the entity's configured session-key purpose.
            count: Number of keys to request. Defaults to ``config.num_keys``.
            timeout: Socket timeout in seconds. Use ``None`` to disable it.

        Returns:
            Session keys returned by Auth.

        Raises:
            ConfigError: If no purpose is available or ``count`` is invalid.
            AuthConnectionError: If Auth cannot be reached.
            AuthProtocolError: If Auth returns an unexpected response.
            CredentialError: If permanent distribution-key credentials are
                unavailable or expired.
        """

        from .auth_service import request_session_keys

        return request_session_keys(
            self,
            purpose=purpose,
            count=count,
            timeout=timeout,
        )

    def connect_secure(
        self,
        *,
        key: SessionKey,
        host: str | None = None,
        port: int | None = None,
        timeout: float | None = 5.0,
    ) -> SecureChannel:
        """Connect to a peer and complete the client-side secure handshake.

        Args:
            key: Session key shared with the peer.
            host: Peer hostname or IP address. Defaults to the first configured
                target when omitted with ``port``.
            port: Peer TCP port. Defaults to the first configured target when
                omitted with ``host``.
            timeout: Connection and handshake timeout in seconds.

        Returns:
            An established ``SecureChannel``.

        Raises:
            ConfigError: If no complete peer address is available.
            AuthConnectionError: If the peer cannot be reached.
            ExpiredKeyError: If ``key`` has expired.
            SecureHandshakeError: If the peer handshake fails validation.
        """

        from .secure_channel import connect_secure

        return connect_secure(
            self,
            key=key,
            host=host,
            port=port,
            timeout=timeout,
        )

    def accept_secure(
        self,
        sock: Any,
        *,
        timeout: float | None = 5.0,
    ) -> SecureChannel:
        """Complete the server-side secure handshake on an accepted socket.

        Args:
            sock: Connected peer socket returned by a listening server.
            timeout: Handshake timeout in seconds.

        Returns:
            An established ``SecureChannel``.

        Raises:
            AuthConnectionError: If the socket closes or communication fails.
            ExpiredKeyError: If the selected session key has expired.
            SecureHandshakeError: If the peer handshake fails validation.
        """

        from .secure_channel import accept_secure

        return accept_secure(self, sock, timeout=timeout)
