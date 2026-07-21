"""Key objects and session-key cache for IoTAuth entities."""

from __future__ import annotations

from dataclasses import dataclass

from .exceptions import KeyCacheError

SESSION_KEY_ID_SIZE = 8


@dataclass
class SessionKey:
    """Session key material and validity metadata shared by peer entities.

    Attributes:
        id: Eight-byte session-key identifier.
        cipher_key: Symmetric encryption key.
        mac_key: Message-authentication key, or ``None`` when HMAC is disabled.
        abs_validity: Absolute expiration time in milliseconds since the epoch.
        rel_validity: Validity duration in milliseconds after first use.
        encryption_mode: Configured symmetric encryption mode.
        hmac_enabled: Whether messages require HMAC authentication.
        permanent_distribution_key: Whether Auth issued the key through
            permanent distribution-key mode.
        first_use_ms: First-use time used to evaluate relative validity.

    Raises:
        KeyCacheError: If the identifier or key material is invalid.
    """

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
    """Symmetric key material used to protect requests sent to Auth.

    Attributes:
        cipher_key: Symmetric encryption key.
        mac_key: Optional message-authentication key.
        abs_validity: Absolute expiration time in milliseconds since the epoch.
        encryption_mode: Configured symmetric encryption mode.

    Raises:
        KeyCacheError: If the cipher key is empty.
    """

    cipher_key: bytes
    mac_key: bytes | None
    abs_validity: int | None
    encryption_mode: str

    def __post_init__(self) -> None:
        if not self.cipher_key:
            raise KeyCacheError("Distribution key cipher_key must not be empty")


class SessionKeyCache:
    """In-memory session-key cache keyed by eight-byte key identifiers."""

    def __init__(self) -> None:
        self._keys: dict[bytes, SessionKey] = {}

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, key_id: bytes) -> bool:
        self._validate_key_id(key_id)
        return key_id in self._keys

    def add(self, key: SessionKey, *, replace: bool = False) -> None:
        """Store a session key.

        Args:
            key: Session key to cache.
            replace: Whether to replace an existing key with the same ID.

        Raises:
            KeyCacheError: If the key ID already exists and ``replace`` is false.
        """

        if key.id in self._keys and not replace:
            raise KeyCacheError(f"Session key already exists: {key.id.hex()}")
        self._keys[key.id] = key

    def get(self, key_id: bytes) -> SessionKey | None:
        """Return a cached key, or ``None`` when its ID is absent.

        Args:
            key_id: Eight-byte session-key identifier.

        Raises:
            KeyCacheError: If ``key_id`` is not eight bytes long.
        """

        self._validate_key_id(key_id)
        return self._keys.get(key_id)

    def require(self, key_id: bytes) -> SessionKey:
        """Return a cached key and fail when its ID is absent.

        Args:
            key_id: Eight-byte session-key identifier.

        Returns:
            The cached session key.

        Raises:
            KeyCacheError: If ``key_id`` is invalid or is not cached.
        """

        key = self.get(key_id)
        if key is None:
            raise KeyCacheError(f"Session key not found: {key_id.hex()}")
        return key

    def values(self) -> tuple[SessionKey, ...]:
        """Return an immutable snapshot of all cached session keys."""

        return tuple(self._keys.values())

    @staticmethod
    def _validate_key_id(key_id: bytes) -> None:
        if len(key_id) != SESSION_KEY_ID_SIZE:
            raise KeyCacheError(
                f"Session key ID must be {SESSION_KEY_ID_SIZE} bytes, got {len(key_id)}"
            )
