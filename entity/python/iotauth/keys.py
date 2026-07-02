"""Key objects and session-key cache for IoTAuth entities."""

from __future__ import annotations

from dataclasses import dataclass

from .exceptions import KeyCacheError

SESSION_KEY_ID_SIZE = 8


@dataclass
class SessionKey:
    id: bytes
    cipher_key: bytes
    mac_key: bytes | None
    abs_validity: int | None
    rel_validity: int | None
    encryption_mode: str
    hmac_enabled: bool
    permanent_distribution_key: bool
    first_use_ms: int | None = None

    def __post_init__(self) -> None:
        if len(self.id) != SESSION_KEY_ID_SIZE:
            raise KeyCacheError(
                f"Session key ID must be {SESSION_KEY_ID_SIZE} bytes, got {len(self.id)}"
            )
        if not self.cipher_key:
            raise KeyCacheError("Session key cipher_key must not be empty")
        if self.hmac_enabled and not self.mac_key:
            raise KeyCacheError("Session key mac_key is required when HMAC is enabled")


@dataclass(frozen=True)
class DistributionKey:
    cipher_key: bytes
    mac_key: bytes | None
    abs_validity: int | None
    encryption_mode: str

    def __post_init__(self) -> None:
        if not self.cipher_key:
            raise KeyCacheError("Distribution key cipher_key must not be empty")


class SessionKeyCache:
    """Small in-memory session-key cache keyed by 8-byte session key ID."""

    def __init__(self) -> None:
        self._keys: dict[bytes, SessionKey] = {}

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, key_id: bytes) -> bool:
        self._validate_key_id(key_id)
        return key_id in self._keys

    def add(self, key: SessionKey, *, replace: bool = False) -> None:
        if key.id in self._keys and not replace:
            raise KeyCacheError(f"Session key already exists: {key.id.hex()}")
        self._keys[key.id] = key

    def get(self, key_id: bytes) -> SessionKey | None:
        self._validate_key_id(key_id)
        return self._keys.get(key_id)

    def require(self, key_id: bytes) -> SessionKey:
        key = self.get(key_id)
        if key is None:
            raise KeyCacheError(f"Session key not found: {key_id.hex()}")
        return key

    def values(self) -> tuple[SessionKey, ...]:
        return tuple(self._keys.values())

    @staticmethod
    def _validate_key_id(key_id: bytes) -> None:
        if len(key_id) != SESSION_KEY_ID_SIZE:
            raise KeyCacheError(
                f"Session key ID must be {SESSION_KEY_ID_SIZE} bytes, got {len(key_id)}"
            )
