# IoTAuth Python API Reference

This document is for developers who want to use the Python IoTAuth entity API.
For the directory map, see [README.md](./README.md). For the step-by-step
implementation diary, see [API_implementation_REDME.md](./API_implementation_REDME.md).

Most application code should import from the package root:

```python
from iotauth import IoTAuthContext, SecureClient, SecureServer
```

Lower-level protocol helpers are also exported from `iotauth`, but they are
mainly useful for testing, debugging, or extending the protocol implementation.

## Quick start

### Create a runtime context

```python
from iotauth import IoTAuthContext

ctx = IoTAuthContext.from_config("path/to/entity.config")
```

`IoTAuthContext` loads the entity config, Auth public key, entity private key,
and creates the in-memory session-key cache.

### Client: request keys and connect securely

```python
from iotauth import IoTAuthContext, SecureClient

ctx = IoTAuthContext.from_config("path/to/client.config")

with SecureClient(ctx) as client:
    channel = client.connect()
    client.send(b"hello")
    reply = client.recv()
```

If no session key is supplied, `SecureClient.connect()` asks Auth for a session
key first, then connects to the configured target server and completes the
secure handshake.

### Server: accept one secure connection

```python
from iotauth import IoTAuthContext, SecureServer

ctx = IoTAuthContext.from_config("path/to/server.config")

with SecureServer(ctx) as server:
    channel = server.serve_once()
    data = channel.recv()
    channel.send(b"ack")
```

The server must already have the session key in `ctx.session_keys` before it can
accept a secure handshake from a peer.

## High-level API

These are the main objects most developers should use.

### `IoTAuthContext`

```python
IoTAuthContext(
    config: EntityConfig,
    auth_public_key: Any,
    entity_private_key: Any,
    distribution_key: DistributionKey | None,
    session_keys: SessionKeyCache,
)
```

Runtime container for config, credentials, distribution key state, and cached
session keys.

#### Constructors

```python
IoTAuthContext.from_config(path: str | Path, *, validate_paths: bool = True) -> IoTAuthContext
IoTAuthContext.from_entity_config(config: EntityConfig) -> IoTAuthContext
```

- `from_config()` parses a C-style dotted config file and loads credentials.
- `from_entity_config()` starts from an already parsed `EntityConfig`.
- Permanent distribution key mode currently raises `CredentialError`; it is not
  implemented yet in the Python API.

#### Methods

```python
ctx.request_session_keys(
    *,
    purpose: dict[str, object] | str | None = None,
    count: int | None = None,
    timeout: float | None = 5.0,
) -> list[SessionKey]
```

Requests session keys from Auth and stores them in `ctx.session_keys`.

```python
ctx.connect_secure(
    *,
    key: SessionKey,
    host: str | None = None,
    port: int | None = None,
    timeout: float | None = 5.0,
) -> SecureChannel
```

Opens a TCP connection and completes the client side of the secure handshake.
If `host` and `port` are omitted, the first configured target server is used.

```python
ctx.accept_secure(sock: Any, *, timeout: float | None = 5.0) -> SecureChannel
```

Completes the server side of the secure handshake on an already accepted socket.

### `SecureClient`

```python
SecureClient(
    ctx: IoTAuthContext,
    *,
    key: SessionKey | None = None,
    purpose: dict[str, object] | str | None = None,
    host: str | None = None,
    port: int | None = None,
    timeout: float | None = 5.0,
)
```

Convenience wrapper for the client workflow.

#### Methods

```python
client.connect() -> SecureChannel
client.send(data: bytes) -> None
client.recv() -> bytes
client.close() -> None
```

- `connect()` requests a session key when `key` is not provided.
- `send()` and `recv()` delegate to the connected `SecureChannel`.
- `close()` closes the active channel if one exists.
- The class supports `with SecureClient(...) as client:`.

### `SecureServer`

```python
SecureServer(
    ctx: IoTAuthContext,
    *,
    host: str | None = None,
    port: int | None = None,
    backlog: int = 5,
    timeout: float | None = 5.0,
)
```

Convenience wrapper for accepting secure IoTAuth TCP connections.

#### Methods

```python
server.listen() -> None
server.serve_once() -> SecureChannel
server.close() -> None
```

- `listen()` binds the socket. If no host/port is supplied, the first configured
  target server is used.
- `serve_once()` accepts one TCP connection and completes the secure handshake.
- `close()` closes the listening socket.
- The class supports `with SecureServer(...) as server:`.

### `SecureChannel`

```python
SecureChannel(
    socket: Any,
    session_key: SessionKey,
    send_sequence: int = 0,
    receive_sequence: int = 0,
    closed: bool = False,
)
```

Encrypted channel created after a successful secure handshake.

#### Methods

```python
channel.send(data: bytes) -> None
channel.recv() -> bytes
channel.close() -> None
```

- `send()` encrypts and authenticates `data`, then sends a `SECURE_COMM_MSG`.
- `recv()` receives one `SECURE_COMM_MSG`, verifies sequence order, decrypts it,
  and returns plaintext bytes.
- `close()` closes the underlying socket and marks the channel closed.

## Config API

### `load_config`

```python
load_config(path: str | Path, *, validate_paths: bool = True) -> EntityConfig
```

Loads and validates an IoTAuth entity config file. By default, referenced key
files must exist. Set `validate_paths=False` in tests or tooling that only needs
to parse config values.

Raises `ConfigError` when the file is missing, malformed, has unknown keys, or
contains unsupported values.

### Config dataclasses

```python
AuthInfo(id: int, host: str, port: int, public_key_path: Path)
EntityInfo(name: str, private_key_path: Path)
TargetServer(host: str, port: int, name: str | None = None)
SessionConfig(
    protocol: str,
    encryption_mode: str,
    distribution_encryption_mode: str,
    hmac_enabled: bool = True,
    permanent_distribution_key: bool = False,
)
EntityConfig(
    entity: EntityInfo,
    auth: AuthInfo,
    session: SessionConfig,
    purposes: list[dict[str, Any] | str],
    num_keys: int,
    targets: list[TargetServer],
    distribution_cipher_key_path: Path | None = None,
    distribution_mac_key_path: Path | None = None,
)
```

Supported protocol: `TCP`.

Supported encryption modes:

- `AES_128_CBC`
- `AES_128_CTR`
- `AES_128_GCM`

## Key API

### `SessionKey`

```python
SessionKey(
    id: bytes,
    cipher_key: bytes,
    mac_key: bytes | None,
    abs_validity: int | None,
    rel_validity: int | None,
    encryption_mode: str,
    hmac_enabled: bool,
    permanent_distribution_key: bool,
)
```

Represents one 8-byte session key record from Auth. `abs_validity` and
`rel_validity` are millisecond values from the protocol.

Validation:

- `id` must be exactly 8 bytes.
- `cipher_key` must not be empty.
- `mac_key` is required when `hmac_enabled=True`.

### `DistributionKey`

```python
DistributionKey(
    cipher_key: bytes,
    mac_key: bytes | None,
    abs_validity: int | None,
    encryption_mode: str,
)
```

Represents the reusable Auth distribution key returned with session keys.

### `SessionKeyCache`

```python
cache = SessionKeyCache(max_keys: int = 10)
```

Small in-memory cache keyed by 8-byte session key ID.

```python
cache.add(key: SessionKey, *, replace: bool = False) -> None
cache.get(key_id: bytes) -> SessionKey | None
cache.require(key_id: bytes) -> SessionKey
cache.has_room(count: int = 1) -> bool
cache.values() -> tuple[SessionKey, ...]
len(cache) -> int
key_id in cache -> bool
```

`require()` raises `KeyCacheError` when the key is missing.

## Auth service API

### `request_session_keys`

```python
request_session_keys(
    ctx: IoTAuthContext,
    *,
    purpose: dict[str, object] | str | None = None,
    count: int | None = None,
    timeout: float | None = 5.0,
) -> list[SessionKey]
```

Requests session keys from Auth over TCP and stores them in `ctx.session_keys`.
This is the function behind `ctx.request_session_keys()` and
`SecureClient.connect()`.

Behavior:

- Uses the supplied `purpose`, otherwise the first purpose in config.
- Uses `count`, otherwise `ctx.config.num_keys`.
- Connects to `ctx.config.auth.host` and `ctx.config.auth.port`.
- Handles both first-time public-key encrypted requests and later
  distribution-key protected requests.

### `distribution_key_is_expired`

```python
distribution_key_is_expired(key: DistributionKey, *, now_ms: int | None = None) -> bool
```

Returns `True` when the distribution key absolute validity has passed.

## Secure channel functions

### `connect_secure`

```python
connect_secure(
    ctx: IoTAuthContext,
    *,
    key: SessionKey,
    host: str | None = None,
    port: int | None = None,
    target: TargetServer | None = None,
    timeout: float | None = 5.0,
) -> SecureChannel
```

Opens a TCP connection and performs the client-side secure handshake.

Target selection:

- Pass `target=TargetServer(...)`, or
- pass `host` and `port` together, or
- omit both to use the first configured target.

### `accept_secure`

```python
accept_secure(
    ctx: IoTAuthContext,
    sock: Any,
    *,
    timeout: float | None = 5.0,
) -> SecureChannel
```

Completes the server-side secure handshake on an accepted socket.

### `session_key_is_expired`

```python
session_key_is_expired(key: SessionKey, *, now_ms: int | None = None) -> bool
```

Returns `True` when the session key absolute validity has passed.

## Message and serialization API

### `MessageType`

`MessageType` is an `IntEnum` of IoTAuth protocol message IDs. Common values:

- `MessageType.AUTH_HELLO`
- `MessageType.AUTH_ALERT`
- `MessageType.SESSION_KEY_REQ_IN_PUB_ENC`
- `MessageType.SESSION_KEY_RESP_WITH_DIST_KEY`
- `MessageType.SESSION_KEY_REQ`
- `MessageType.SESSION_KEY_RESP`
- `MessageType.SKEY_HANDSHAKE_1`
- `MessageType.SKEY_HANDSHAKE_2`
- `MessageType.SKEY_HANDSHAKE_3`
- `MessageType.SECURE_COMM_MSG`

### `IoTSPFrame`

```python
IoTSPFrame(message_type: MessageType, payload: bytes)
```

Container for one protocol frame. `payload` must be bytes.

### Frame helpers

```python
serialize_frame(frame: IoTSPFrame) -> bytes
parse_frame(data: bytes, *, allow_trailing: bool = False) -> IoTSPFrame
send_frame(sock: Any, frame: IoTSPFrame) -> None
recv_frame(sock: Any, *, max_payload_size: int = 65536) -> IoTSPFrame
```

Use `send_frame()` and `recv_frame()` when working directly with TCP sockets.
The default `recv_frame()` maximum payload size is 65,536 bytes.

### Integer helpers

```python
encode_varint(value: int) -> bytes
decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]
encode_uint_be(value: int, length: int) -> bytes
decode_uint_be(data: bytes) -> int
```

These helpers implement the binary integer encodings used by IoTSP frames and
payloads.

## Auth payload API

### Payload dataclasses

```python
AuthHelloPayload(auth_id: int, nonce: bytes)
AuthAlertPayload(code: int)
SessionKeyRequestPayload(
    entity_nonce: bytes,
    auth_nonce: bytes,
    num_keys: int,
    entity_name: str,
    purpose: dict[str, Any] | str,
    diffie_hellman_param: bytes | None = None,
)
SessionKeyResponsePayload(
    entity_nonce: bytes,
    crypto_spec: dict[str, Any] | str,
    session_keys: list[SessionKey],
)
```

### Payload helpers

```python
parse_auth_hello_payload(payload: bytes) -> AuthHelloPayload
parse_auth_alert_payload(payload: bytes) -> AuthAlertPayload
serialize_session_key_request_payload(request: SessionKeyRequestPayload) -> bytes
parse_session_key_response_payload(
    payload: bytes,
    session_config: SessionConfig,
    *,
    allow_trailing: bool = False,
) -> SessionKeyResponsePayload
parse_distribution_key_record(
    data: bytes,
    *,
    offset: int = 0,
    encryption_mode: str = "AES_128_CBC",
    allow_trailing: bool = False,
) -> DistributionKey
parse_session_key_record(data: bytes, offset: int, session_config: SessionConfig) -> tuple[SessionKey, int]
serialize_buffered_string(value: str) -> bytes
parse_buffered_string(data: bytes, offset: int = 0) -> tuple[str, int]
```

Constants:

```python
AUTH_ID_SIZE = 4
NONCE_SIZE = 8
```

## Handshake API

### `HandshakePayload`

```python
HandshakePayload(
    nonce: bytes | None = None,
    reply_nonce: bytes | None = None,
    diffie_hellman_param: bytes | None = None,
)
```

Cleartext representation of a secure handshake payload before encryption.

### Handshake helpers

```python
serialize_handshake_payload(payload: HandshakePayload) -> bytes
parse_handshake_payload(data: bytes) -> HandshakePayload
build_handshake_1(key: SessionKey, client_nonce: bytes) -> bytes
parse_handshake_1_key_id(payload: bytes) -> bytes
verify_handshake_1_and_build_handshake_2(
    key: SessionKey,
    handshake_1_payload: bytes,
    server_nonce: bytes,
) -> tuple[bytes, bytes]
verify_handshake_2_and_build_handshake_3(
    key: SessionKey,
    encrypted_handshake_2: bytes,
    client_nonce: bytes,
) -> tuple[bytes, bytes]
verify_handshake_3(
    key: SessionKey,
    encrypted_handshake_3: bytes,
    server_nonce: bytes,
) -> HandshakePayload
```

Most applications should not call these directly. They are used by
`connect_secure()` and `accept_secure()`.

## Crypto API

These helpers wrap the cryptographic operations used by the protocol.

```python
public_encrypt(payload: bytes, public_key: Any) -> bytes
private_decrypt(ciphertext: bytes, private_key: Any) -> bytes
sign_sha256(data: bytes, private_key: Any) -> bytes
verify_sha256(data: bytes, signature: bytes, public_key: Any) -> None
encrypt_and_sign_for_auth(payload: bytes, ctx: IoTAuthContext) -> bytes
verify_and_decrypt_from_auth(payload: bytes, ctx: IoTAuthContext, encrypted_size: int) -> bytes
symmetric_encrypt_authenticate(
    plaintext: bytes,
    cipher_key: bytes,
    mac_key: bytes | None,
    encryption_mode: str,
    hmac_enabled: bool,
) -> bytes
symmetric_decrypt_authenticate(
    envelope: bytes,
    cipher_key: bytes,
    mac_key: bytes | None,
    encryption_mode: str,
    hmac_enabled: bool,
) -> bytes
encrypt_request_with_distribution_key(
    payload: bytes,
    sender_name: str,
    distribution_key: DistributionKey,
    *,
    hmac_enabled: bool = False,
) -> bytes
decrypt_request_with_distribution_key(
    protected_payload: bytes,
    distribution_key: DistributionKey,
    *,
    hmac_enabled: bool = False,
) -> tuple[str, bytes]
```

Most application code should use the higher-level context, client, server, and
channel APIs instead of calling crypto helpers directly.

## Credential API

```python
load_auth_public_key(path: str | Path) -> Any
load_entity_private_key(path: str | Path) -> Any
```

Loads PEM-encoded Auth public keys and entity private keys using the
`cryptography` backend.

## Exceptions

All custom exceptions inherit from `IoTAuthError`.

| Exception | Meaning |
| --- | --- |
| `IoTAuthError` | Base class for API-specific errors. |
| `ConfigError` | Config file is missing, malformed, or unsupported. |
| `CredentialError` | Key/certificate material could not be loaded or is unsupported. |
| `KeyCacheError` | Session or distribution key state is invalid. |
| `SerializationError` | Bytes could not be encoded or decoded as expected. |
| `AuthConnectionError` | Network connection/listen/receive problem. |
| `AuthProtocolError` | Auth returned an unexpected or invalid protocol message. |
| `UnsupportedCryptoError` | Requested crypto mode or backend support is missing. |
| `MessageIntegrityError` | Signature, MAC, tag, or authentication check failed. |
| `SecureHandshakeError` | Secure handshake failed validation. |
| `ExpiredKeyError` | A session key was used after expiration. |
| `SecureChannelClosed` | Operation attempted on a closed secure channel. |
| `InvalidSequenceNumberError` | Secure message sequence number was invalid. |

Typical usage:

```python
from iotauth import IoTAuthError, SecureClient

try:
    with SecureClient(ctx) as client:
        client.connect()
        client.send(b"hello")
except IoTAuthError as exc:
    print(f"IoTAuth operation failed: {exc}")
```

## Import guide

Recommended imports for application code:

```python
from iotauth import IoTAuthContext, SecureClient, SecureServer, IoTAuthError
```

Recommended imports for lower-level protocol tests:

```python
from iotauth import (
    IoTSPFrame,
    MessageType,
    SessionKey,
    SessionKeyCache,
    parse_frame,
    serialize_frame,
)
```

## Current limitations

- Permanent distribution key mode is not implemented in the Python API yet.
- The server-side secure handshake requires the matching session key to already
  be present in `ctx.session_keys`.
- The high-level server currently exposes `serve_once()` rather than a forever
  loop; applications can build their own loop around it.
- The API is synchronous and TCP-focused.
