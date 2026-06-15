"""Runtime context for IoTAuth Python entities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import EntityConfig, load_config
from .credentials import load_auth_public_key, load_entity_private_key
from .exceptions import CredentialError
from .keys import DistributionKey, SessionKey, SessionKeyCache


@dataclass
class IoTAuthContext:
    config: EntityConfig
    auth_public_key: Any
    entity_private_key: Any
    distribution_key: DistributionKey | None
    session_keys: SessionKeyCache

    @classmethod
    def from_config(
        cls, path: str | Path, *, validate_paths: bool = True
    ) -> "IoTAuthContext":
        config = load_config(path, validate_paths=validate_paths)
        return cls.from_entity_config(config)

    @classmethod
    def from_entity_config(cls, config: EntityConfig) -> "IoTAuthContext":
        if config.session.permanent_distribution_key:
            raise CredentialError(
                "Permanent distribution key mode is not implemented in the "
                "Python API yet"
            )

        return cls(
            config=config,
            auth_public_key=load_auth_public_key(config.auth.public_key_path),
            entity_private_key=load_entity_private_key(
                config.entity.private_key_path
            ),
            distribution_key=None,
            session_keys=SessionKeyCache(),
        )

    def request_session_keys(
        self,
        *,
        purpose: dict[str, object] | str | None = None,
        count: int | None = None,
        timeout: float | None = 5.0,
    ) -> list[SessionKey]:
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
    ) -> Any:
        from .secure_channel import connect_secure

        return connect_secure(
            self,
            key=key,
            host=host,
            port=port,
            timeout=timeout,
        )
