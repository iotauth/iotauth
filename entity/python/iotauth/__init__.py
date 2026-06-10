"""Python entity API for IoTAuth."""

from .config import (
    AuthInfo,
    EntityConfig,
    EntityInfo,
    SessionConfig,
    TargetServer,
    load_config,
)
from .context import IoTAuthContext
from .exceptions import (
    ConfigError,
    CredentialError,
    IoTAuthError,
    KeyCacheError,
    SerializationError,
)
from .keys import DistributionKey, SessionKey, SessionKeyCache
from .messages import IoTSPFrame, MessageType, message_type_from_byte
from .serialization import (
    decode_uint_be,
    decode_varint,
    encode_uint_be,
    encode_varint,
    parse_frame,
    serialize_frame,
)

__all__ = [
    "AuthInfo",
    "ConfigError",
    "CredentialError",
    "decode_uint_be",
    "decode_varint",
    "DistributionKey",
    "encode_uint_be",
    "encode_varint",
    "EntityConfig",
    "EntityInfo",
    "IoTAuthContext",
    "IoTAuthError",
    "IoTSPFrame",
    "KeyCacheError",
    "MessageType",
    "message_type_from_byte",
    "parse_frame",
    "SerializationError",
    "serialize_frame",
    "SessionConfig",
    "SessionKey",
    "SessionKeyCache",
    "TargetServer",
    "load_config",
]
