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


class AuthConnectionError(IoTAuthError):
    """Raised when TCP communication with Auth fails."""


class AuthProtocolError(IoTAuthError):
    """Raised when Auth protocol bytes are valid but semantically unexpected."""


class UnsupportedCryptoError(IoTAuthError):
    """Raised when a requested crypto operation or backend is unsupported."""


class MessageIntegrityError(IoTAuthError):
    """Raised when signature, MAC, or authenticated decryption verification fails."""


class SecureHandshakeError(IoTAuthError):
    """Raised when a secure entity handshake fails."""


class ExpiredKeyError(IoTAuthError):
    """Raised when an expired key is used for a secure operation."""
