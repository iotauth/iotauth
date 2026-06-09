"""Exception types used by the IoTAuth Python API."""


class IoTAuthError(Exception):
    """Base class for all IoTAuth Python API errors."""


class ConfigError(IoTAuthError):
    """Raised when an entity config file is missing, malformed, or invalid."""
