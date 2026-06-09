"""Config parsing for IoTAuth Python entities.

The parser intentionally starts with the C-style dotted ``.config`` files used
by the existing entity examples. It returns typed dataclasses so later modules
can consume validated configuration instead of raw strings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .exceptions import ConfigError


SUPPORTED_PROTOCOLS = {"TCP"}
SUPPORTED_ENCRYPTION_MODES = {"AES_128_CBC", "AES_128_CTR", "AES_128_GCM"}

REQUIRED_KEYS = {
    "entityInfo.name",
    "entityInfo.number_key",
    "authInfo.id",
    "sessionKey.encryptionMode",
    "authInfo.pubkey.path",
    "entityInfo.privkey.path",
    "auth.ip.address",
    "auth.port.number",
    "entity.server.ip.address",
    "entity.server.port.number",
    "network.protocol",
}

OPTIONAL_KEYS = {
    "entityInfo.purpose",
    "HmacMode",
    "PermanentDistKeyMode",
    "distKey.encryptionMode",
    "distKey.cipherkey.path",
    "distkey.mackey.path",
    "fileSystemManager.ip.address",
    "fileSystemManager.port.number",
}


@dataclass(frozen=True)
class AuthInfo:
    id: int
    host: str
    port: int
    public_key_path: Path


@dataclass(frozen=True)
class EntityInfo:
    name: str
    private_key_path: Path


@dataclass(frozen=True)
class TargetServer:
    host: str
    port: int
    name: str | None = None


@dataclass(frozen=True)
class SessionConfig:
    protocol: str
    encryption_mode: str
    distribution_encryption_mode: str
    hmac_enabled: bool = True
    permanent_distribution_key: bool = False


@dataclass(frozen=True)
class EntityConfig:
    entity: EntityInfo
    auth: AuthInfo
    session: SessionConfig
    purposes: list[dict[str, Any] | str]
    num_keys: int
    targets: list[TargetServer]
    distribution_cipher_key_path: Path | None = None
    distribution_mac_key_path: Path | None = None


def load_config(path: str | Path, *, validate_paths: bool = True) -> EntityConfig:
    """Load and validate an IoTAuth entity config file.

    Args:
        path: Path to a C-style dotted property config file.
        validate_paths: When true, referenced key files must exist.

    Raises:
        ConfigError: If the file is missing, malformed, or contains invalid
            values.
    """

    config_path = Path(path).expanduser()
    if not config_path.exists():
        raise ConfigError(f"Config file does not exist: {config_path}")
    if not config_path.is_file():
        raise ConfigError(f"Config path is not a file: {config_path}")

    raw = _read_properties(config_path)
    _reject_unknown_keys(raw)
    _require_keys(raw, REQUIRED_KEYS)

    entity_name = _require_non_empty(raw, "entityInfo.name")
    auth_id = _parse_int(raw, "authInfo.id")
    auth_host = _require_non_empty(raw, "auth.ip.address")
    auth_port = _parse_port(raw, "auth.port.number")
    num_keys = _parse_int(raw, "entityInfo.number_key")
    if num_keys < 1:
        raise ConfigError("entityInfo.number_key must be at least 1")

    protocol = _require_non_empty(raw, "network.protocol").upper()
    if protocol not in SUPPORTED_PROTOCOLS:
        supported = ", ".join(sorted(SUPPORTED_PROTOCOLS))
        raise ConfigError(f"Unsupported network.protocol {protocol!r}; supported: {supported}")

    encryption_mode = _parse_encryption_mode(raw, "sessionKey.encryptionMode")
    distribution_encryption_mode = (
        _parse_encryption_mode(raw, "distKey.encryptionMode")
        if "distKey.encryptionMode" in raw
        else encryption_mode
    )

    hmac_enabled = _parse_on_off(raw.get("HmacMode", "on"), "HmacMode")
    permanent_dist_key = _parse_on_off(
        raw.get("PermanentDistKeyMode", "off"), "PermanentDistKeyMode"
    )

    auth_public_key = _resolve_path(
        config_path, raw["authInfo.pubkey.path"], "authInfo.pubkey.path", validate_paths
    )
    entity_private_key = _resolve_path(
        config_path,
        raw["entityInfo.privkey.path"],
        "entityInfo.privkey.path",
        validate_paths,
    )

    dist_cipher_key = _resolve_optional_path(
        config_path, raw, "distKey.cipherkey.path", validate_paths
    )
    dist_mac_key = _resolve_optional_path(
        config_path, raw, "distkey.mackey.path", validate_paths
    )

    targets = _parse_targets(raw)
    purposes = _parse_purposes(raw)

    return EntityConfig(
        entity=EntityInfo(name=entity_name, private_key_path=entity_private_key),
        auth=AuthInfo(
            id=auth_id,
            host=auth_host,
            port=auth_port,
            public_key_path=auth_public_key,
        ),
        session=SessionConfig(
            protocol=protocol,
            encryption_mode=encryption_mode,
            distribution_encryption_mode=distribution_encryption_mode,
            hmac_enabled=hmac_enabled,
            permanent_distribution_key=permanent_dist_key,
        ),
        purposes=purposes,
        num_keys=num_keys,
        targets=targets,
        distribution_cipher_key_path=dist_cipher_key,
        distribution_mac_key_path=dist_mac_key,
    )


def _read_properties(config_path: Path) -> dict[str, str]:
    result: dict[str, str] = {}

    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigError(f"Could not read config file {config_path}: {exc}") from exc

    for line_number, original_line in enumerate(lines, start=1):
        line = original_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "=" not in line:
            raise ConfigError(f"Line {line_number} must contain '=': {original_line!r}")

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ConfigError(f"Line {line_number} has an empty config key")
        if not value:
            raise ConfigError(f"Config value for {key!r} on line {line_number} is empty")
        if key in result:
            raise ConfigError(f"Duplicate config key {key!r} on line {line_number}")
        result[key] = value

    return result


def _reject_unknown_keys(raw: dict[str, str]) -> None:
    for key in raw:
        if key in REQUIRED_KEYS or key in OPTIONAL_KEYS:
            continue
        if _is_target_server_key(key):
            continue
        raise ConfigError(f"Unknown config key: {key}")


def _require_keys(raw: dict[str, str], required_keys: set[str]) -> None:
    missing = sorted(required_keys - raw.keys())
    if missing:
        raise ConfigError(f"Missing required config key(s): {', '.join(missing)}")


def _require_non_empty(raw: dict[str, str], key: str) -> str:
    value = raw[key].strip()
    if not value:
        raise ConfigError(f"{key} must not be empty")
    return value


def _parse_int(raw: dict[str, str], key: str) -> int:
    value = _require_non_empty(raw, key)
    try:
        return int(value, 10)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer, got {value!r}") from exc


def _parse_port(raw: dict[str, str], key: str) -> int:
    port = _parse_int(raw, key)
    if not 1 <= port <= 65535:
        raise ConfigError(f"{key} must be in range 1..65535, got {port}")
    return port


def _parse_encryption_mode(raw: dict[str, str], key: str) -> str:
    mode = _require_non_empty(raw, key)
    if mode not in SUPPORTED_ENCRYPTION_MODES:
        supported = ", ".join(sorted(SUPPORTED_ENCRYPTION_MODES))
        raise ConfigError(f"Unsupported {key} {mode!r}; supported: {supported}")
    return mode


def _parse_on_off(value: str, key: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"on", "1", "true", "yes"}:
        return True
    if normalized in {"off", "0", "false", "no"}:
        return False
    raise ConfigError(f"{key} must be on/off, 1/0, true/false, or yes/no")


def _resolve_path(
    config_path: Path, value: str, key: str, validate_paths: bool
) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = config_path.parent / candidate
    candidate = candidate.resolve(strict=False)

    if validate_paths and not candidate.is_file():
        raise ConfigError(f"{key} does not point to an existing file: {candidate}")
    return candidate


def _resolve_optional_path(
    config_path: Path, raw: dict[str, str], key: str, validate_paths: bool
) -> Path | None:
    if key not in raw:
        return None
    return _resolve_path(config_path, raw[key], key, validate_paths)


def _parse_purposes(raw: dict[str, str]) -> list[dict[str, Any] | str]:
    if "entityInfo.purpose" not in raw:
        return []

    purpose = raw["entityInfo.purpose"]
    try:
        parsed = json.loads(purpose)
    except json.JSONDecodeError:
        return [purpose]

    if not isinstance(parsed, dict):
        raise ConfigError("entityInfo.purpose must be a JSON object or raw purpose string")
    return [parsed]


def _parse_targets(raw: dict[str, str]) -> list[TargetServer]:
    targets = [
        TargetServer(
            host=_require_non_empty(raw, "entity.server.ip.address"),
            port=_parse_port(raw, "entity.server.port.number"),
        )
    ]

    indexed_targets: dict[int, dict[str, str]] = {}
    prefix_map = {
        "targetServerInfo.name_": "name",
        "targetServerInfo.host_": "host",
        "targetServerInfo.port_": "port",
    }
    for key, value in raw.items():
        for prefix, field in prefix_map.items():
            if key.startswith(prefix):
                index = _parse_target_index(key, prefix)
                indexed_targets.setdefault(index, {})[field] = value

    for index in sorted(indexed_targets):
        target = indexed_targets[index]
        missing = sorted({"host", "port"} - target.keys())
        if missing:
            raise ConfigError(
                f"targetServerInfo entry {index} is missing: {', '.join(missing)}"
            )
        port_raw = {"targetServerInfo.port": target["port"]}
        targets.append(
            TargetServer(
                name=target.get("name"),
                host=target["host"],
                port=_parse_port(port_raw, "targetServerInfo.port"),
            )
        )

    return targets


def _is_target_server_key(key: str) -> bool:
    prefixes = (
        "targetServerInfo.name_",
        "targetServerInfo.host_",
        "targetServerInfo.port_",
    )
    return any(key.startswith(prefix) and key[len(prefix) :].isdigit() for prefix in prefixes)


def _parse_target_index(key: str, prefix: str) -> int:
    suffix = key[len(prefix) :]
    if not suffix.isdigit():
        raise ConfigError(f"Invalid targetServerInfo index in key: {key}")
    return int(suffix, 10)
