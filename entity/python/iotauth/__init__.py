"""Public Python API for IoTAuth entities.

Protocol, cryptographic, handshake, serialization, and transport helpers live
in their dedicated modules and are intentionally not re-exported here.
"""

from .client import SecureClient
from .config import (
    AuthInfo,
    EntityConfig,
    EntityInfo,
    SessionConfig,
    TargetServer,
)
from .context import IoTAuthContext
from .exceptions import (
    AuthConnectionError,
    AuthProtocolError,
    ConfigError,
    CredentialError,
    ExpiredKeyError,
    InvalidSequenceNumberError,
    IoTAuthError,
    KeyCacheError,
    MessageIntegrityError,
    SecureChannelClosed,
    SecureClientStateError,
    SecureHandshakeError,
    SerializationError,
    UnsupportedCryptoError,
)
from .keys import DistributionKey, SessionKey, SessionKeyCache
from .secure_channel import SecureChannel
from .server import SecureServer

__all__ = [
    "AuthConnectionError",
    "AuthInfo",
    "AuthProtocolError",
    "ConfigError",
    "CredentialError",
    "DistributionKey",
    "EntityConfig",
    "EntityInfo",
    "ExpiredKeyError",
    "InvalidSequenceNumberError",
    "IoTAuthContext",
    "IoTAuthError",
    "KeyCacheError",
    "MessageIntegrityError",
    "SecureChannel",
    "SecureChannelClosed",
    "SecureClient",
    "SecureClientStateError",
    "SecureHandshakeError",
    "SecureServer",
    "SerializationError",
    "SessionConfig",
    "SessionKey",
    "SessionKeyCache",
    "TargetServer",
    "UnsupportedCryptoError",
]
