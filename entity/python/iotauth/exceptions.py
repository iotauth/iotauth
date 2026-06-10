"""Exception types used by the IoTAuth Python API."""


class IoTAuthError(Exception):
    """Base class for all IoTAuth Python API errors."""


class ConfigError(IoTAuthError):
    """Raised when an entity config file is missing, malformed, or invalid."""


class CredentialError(IoTAuthError):
    """Raised when a credential file cannot be loaded or is unsupported."""


class KeyCacheError(IoTAuthError):
    """Raised when a session key cache operation is invalid."""


class SerializationError(IoTAuthError):
    """Raised when binary protocol serialization or parsing fails."""
