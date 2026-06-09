# IoTAuth Python Entity API

This directory is the planning home for a new Python implementation of the
IoTAuth entity APIs. We are starting the Python API from scratch. The existing
`entity_server.py` file is historical and should not guide the new design for
now.

The goal is to make Python entities first-class IoTAuth participants: they
should be able to request session keys from Auth, establish secure
entity-to-entity communication, send and receive protected messages, and
eventually support delegated access, migration, publish/subscribe, and file
sharing workflows.

## Design goals

- Provide a small, readable Python API for application developers.
- Preserve compatibility with the IoTAuth wire protocol used by the Java Auth
  server, C entity API, and Node.js entity API.
- Keep protocol details available for tests and advanced users without forcing
  every application to handle buffers, sequence numbers, and message framing.
- Support TCP first. UDP can follow once the TCP handshake and secure message
  path are stable.
- Treat keys, nonces, signatures, MACs, and sequence numbers as explicit
  security-sensitive objects.
- Prefer typed dataclasses and clear exceptions over loosely shaped dictionaries.
- Keep the implementation modular enough that crypto, config parsing, message
  encoding, and socket transport can be tested independently.

## Non-goals for the first implementation

- Reusing or extending `entity_server.py`.
- Supporting every Node.js accessor feature in the first milestone.
- Adding a web framework dependency.
- Hiding all protocol behavior behind one monolithic class.
- Inventing a new config format that cannot interoperate with existing IoTAuth
  examples.

## Proposed package layout

```text
entity/python/
  README.md
  pyproject.toml
  iotauth/
    __init__.py
    config.py
    context.py
    crypto.py
    exceptions.py
    keys.py
    messages.py
    secure_channel.py
    client.py
    server.py
    auth_service.py
    transports/
      __init__.py
      tcp.py
      udp.py
    serialization/
      __init__.py
      binary.py
      properties.py
  examples/
    client.py
    server.py
    echo_client.py
    echo_server.py
    configs/
  tests/
```

Suggested responsibilities:

- `config.py`: parse and validate entity config files.
- `context.py`: load config, keys, crypto specs, and caches into an `IoTAuthContext`.
- `keys.py`: represent distribution keys, session keys, key lists, and key IDs.
- `crypto.py`: cryptographic operations only.
- `messages.py`: IoTAuth message types and binary serialization.
- `auth_service.py`: session key requests, migration requests, privilege
  requests, and future Auth-facing workflows.
- `secure_channel.py`: secure handshake, encrypted message framing, sequence
  numbers, send/receive helpers.
- `client.py`: ergonomic client API for connecting to secure entity servers.
- `server.py`: ergonomic server API for accepting secure entity clients.
- `transports/`: TCP and later UDP socket adapters.

## Public API sketch

The high-level API should be pleasant for normal Python applications:

```python
from iotauth import IoTAuthContext, SecureClient

ctx = IoTAuthContext.from_config("configs/net1/client.config")

with SecureClient(ctx) as client:
    client.connect("net1.server")
    client.send(b"hello")
    reply = client.recv()
```

Server-side applications should be similarly direct:

```python
from iotauth import IoTAuthContext, SecureServer

ctx = IoTAuthContext.from_config("configs/net1/server.config")

server = SecureServer(ctx)

@server.on_message
def handle_message(connection, data):
    connection.send(b"ack: " + data)

server.serve_forever()
```

Lower-level APIs should remain available:

```python
ctx = IoTAuthContext.from_config("configs/net1/client.config")
keys = ctx.auth.request_session_keys(purpose={"group": "Servers"}, count=3)
channel = ctx.secure_channel.connect(host="127.0.0.1", port=21100, key=keys[0])
channel.send(b"payload")
```

## Core concepts

### IoTAuthContext

`IoTAuthContext` is the root object for an entity process. It should own:

- Entity identity: name, group, private key.
- Auth identity: Auth ID, host, port, public key.
- Crypto specs: distribution key crypto, session key crypto, signature crypto.
- Transport choices: TCP first, UDP later.
- Session key cache.
- Distribution key, including permanent distribution key mode when configured.
- Target server registry loaded from config.

Proposed constructor:

```python
ctx = IoTAuthContext.from_config(path)
```

Important methods:

- `request_session_keys(purpose=None, count=None) -> list[SessionKey]`
- `get_session_key_by_id(key_id) -> SessionKey`
- `target_server(name=None) -> TargetServer`
- `save_session_keys(path, password=None)`
- `load_session_keys(path, password=None)`

### SessionKey

A session key should be a typed object, not a raw dictionary.

Fields:

- `id: bytes`
- `cipher_key: bytes`
- `mac_key: bytes | None`
- `abs_validity: datetime | None`
- `rel_validity: int | None`
- `encryption_mode: EncryptionMode`
- `hmac_mode: HmacMode`
- `permanent_distribution_key: bool`

Open decision: whether key IDs should be exposed primarily as `bytes`, `int`,
or a small `KeyId` wrapper. The C API stores 8 bytes and includes a helper to
convert to integer; Python can support both while keeping bytes canonical.

### DistributionKey

Used to decrypt and authenticate session key responses from Auth.

Fields:

- `cipher_key: bytes`
- `mac_key: bytes | None`
- `abs_validity: datetime | None`
- `encryption_mode: EncryptionMode`

### SecureChannel

Represents one secure entity-to-entity connection after handshake.

Responsibilities:

- Run the session-key handshake.
- Encrypt outbound application data.
- Authenticate inbound data.
- Track send and receive sequence numbers.
- Reject replayed, skipped, malformed, expired, or unauthenticated messages.
- Send and receive `SECURE_COMM_MSG`.
- Close using `FIN_SECURE_COMM` when possible.

## Config format

Python should initially support the dotted property format used by the C
examples because it is simple and already present in the repository:

```properties
entityInfo.name=net1.client
entityInfo.purpose={"group":"Servers"}
entityInfo.number_key=3
authInfo.id=101
sessionKey.encryptionMode=AES_128_CBC
authInfo.pubkey.path=../../../../auth_certs/Auth101EntityCert.pem
entityInfo.privkey.path=../../../../credentials/keys/net1/Net1.ClientKey.pem
auth.ip.address=127.0.0.1
auth.port.number=21900
entity.server.ip.address=127.0.0.1
entity.server.port.number=21100
network.protocol=TCP
```

The parser should ignore blank lines and comments. Values should be validated
early, with clear errors for missing keys, unknown encryption modes, bad ports,
and unreadable key files.

## Step 1: config parser design

The first implementation step should be the config parser. In C, IoTAuth stores
parsed config in a struct like this:

```c
typedef struct {
    char name[MAX_ENTITY_NAME_LENGTH + 1];
    int numkey;
    int auth_id;
    char auth_pubkey_path[MAX_PATH_LEN];
    char entity_privkey_path[MAX_PATH_LEN];
    char auth_ip_addr[INET_ADDRSTRLEN];
    int auth_port_num;
    char entity_server_ip_addr[INET_ADDRSTRLEN];
    int entity_server_port_num;
    char network_protocol[NETWORK_PROTOCOL_NAME_LENGTH];
} config_t;
```

The Python equivalent should be a set of small dataclasses. A dataclass is close
to a C struct: it groups related fields together, but Python also gives us
constructors, readable printing, equality checks, and type annotations.

Proposed Python model:

```python
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
    hmac_enabled: bool = True
    permanent_distribution_key: bool = False


@dataclass(frozen=True)
class EntityConfig:
    entity: EntityInfo
    auth: AuthInfo
    session: SessionConfig
    purposes: list[dict[str, object]]
    num_keys: int
    targets: list[TargetServer]
```

The first parser function should probably look like this:

```python
def load_config(path: str | Path) -> EntityConfig:
    ...
```

This means application code can start with:

```python
config = load_config("examples/configs/client.config")
```

Later, `IoTAuthContext.from_config(...)` can call `load_config(...)`, then load
the public/private keys, initialize caches, and prepare Auth communication.

### Why this comes first

The config parser is a good first slice because it has almost no cryptography
or networking risk. It lets us define the shape of the rest of the API before
we touch sockets or encrypted payloads.

It also teaches a core Python API pattern:

- C API: parse into a mutable struct and pass pointers around.
- Python API: parse into typed objects and pass those objects around.

### Parser responsibilities

The config parser should:

- Read a `.config` file from disk.
- Ignore blank lines.
- Ignore comment lines that begin with `#` or `//`.
- Split each config line on the first `=`.
- Trim whitespace around keys and values.
- Convert integer fields such as ports, Auth ID, and key counts.
- Parse `entityInfo.purpose` as JSON when possible.
- Resolve relative key paths relative to the config file location.
- Apply defaults for optional fields.
- Raise `ConfigError` with a helpful message when the file is invalid.

### Required fields for milestone 1

Client and server configs should require:

- `entityInfo.name`
- `entityInfo.number_key`
- `authInfo.id`
- `sessionKey.encryptionMode`
- `authInfo.pubkey.path`
- `entityInfo.privkey.path`
- `auth.ip.address`
- `auth.port.number`
- `entity.server.ip.address`
- `entity.server.port.number`
- `network.protocol`

`entityInfo.purpose` should also be required for session key requests, but the
server may use a key-ID purpose such as:

```properties
entityInfo.purpose={"keyId":00000000}
```

Open issue: this value is not strict JSON because `00000000` is not quoted.
The parser can initially keep this as a raw string, then later normalize it
once we confirm how Auth expects the purpose payload.

### Defaults

Suggested defaults:

- `network.protocol`: no default; require `TCP` for now.
- `sessionKey.encryptionMode`: no default in Python milestone 1; require it so
  bad configs fail early.
- `HmacMode`: default to enabled.
- `PermanentDistKeyMode`: default to disabled.
- `distKey.encryptionMode`: default to the session encryption mode.

### Validation rules

The parser should reject:

- Unknown config keys.
- Missing required fields.
- Empty entity name.
- Non-integer ports, Auth IDs, or key counts.
- Ports outside `1..65535`.
- `entityInfo.number_key` less than `1`.
- Unsupported protocols other than `TCP` in milestone 1.
- Unsupported encryption modes outside `AES_128_CBC`, `AES_128_CTR`, and
  `AES_128_GCM`.
- Key paths that do not exist.

### Learning notes

Topics worth studying before or during this step:

- `dataclasses`: Python's closest everyday equivalent to simple C structs.
  <https://docs.python.org/3/library/dataclasses.html>
- `pathlib.Path`: path handling without manual string concatenation.
  <https://docs.python.org/3/library/pathlib.html>
- `typing`: documents what a function expects and returns.
  <https://docs.python.org/3/library/typing.html>
- Exceptions: Python's usual replacement for C-style error return codes.
  <https://docs.python.org/3/tutorial/errors.html>

### Step 1 implementation references

The Step 1 config parser has now been implemented.

Python files:

- `entity/python/iotauth/config.py`
  - `AuthInfo`, `EntityInfo`, `TargetServer`, `SessionConfig`, and
    `EntityConfig`: the Python dataclasses that replace the C-style config
    struct for application-facing code.
  - `load_config(path, validate_paths=True)`: public parser entry point.
  - `_read_properties(...)`: reads dotted `key=value` config files.
  - `_require_keys(...)`, `_parse_int(...)`, `_parse_port(...)`,
    `_parse_encryption_mode(...)`: validation helpers.
  - `_resolve_path(...)`: resolves key paths relative to the config file.
  - `_parse_purposes(...)`: parses `entityInfo.purpose` as JSON when possible,
    otherwise keeps the original raw string.
  - `_parse_targets(...)`: builds the configured secure entity server targets.
- `entity/python/iotauth/exceptions.py`
  - `IoTAuthError`: base exception for this Python API.
  - `ConfigError`: raised for invalid config files.
- `entity/python/iotauth/__init__.py`
  - Exports the public Step 1 API so users can import with
    `from iotauth import load_config`.
- `entity/python/tests/test_config.py`
  - Unit tests for valid configs, raw purpose strings, missing required keys,
    invalid integers, unsupported protocols, and missing key files.

C references this mirrors:

- `entity/c/src/c_api.h`
  - `config_t`: the C struct that stores parsed config fields.
  - `AES_encryption_mode_t`, `hmac_mode_t`, and `perm_dist_key_mode_t`: C
    enums represented as validated Python strings/booleans for now.
- `entity/c/src/load_config.h`
  - `config_type_t`: the C enum of known config keys.
  - `load_config(config_t* c, const char* path)`: the C parser entry point.
- `entity/c/src/load_config.c`
  - `get_key_value(...)`: maps config key strings to C enum values.
  - `load_config(...)`: reads each line, validates known keys, fills `config_t`.
  - `safe_config_value_copy(...)`: C string safety helper. Python does not need
    fixed-size buffers here, but we still validate empty or malformed values.
- `entity/c/examples/server_client_example/c_client.config`
  - Existing C-style client config used as the parser format model.
- `entity/c/examples/server_client_example/c_server.config`
  - Existing C-style server config used as the parser format model.

Verification command:

```sh
PYTHONPATH=entity/python python3 -m unittest discover -s entity/python/tests
```

Recommended normalized Python model:

```python
EntityConfig(
    entity=EntityInfo(name="net1.client", group=None, private_key_path=...),
    auth=AuthInfo(id=101, host="127.0.0.1", port=21900, public_key_path=...),
    session=SessionConfig(protocol="TCP", encryption_mode="AES_128_CBC"),
    purposes=[{"group": "Servers"}],
    num_keys=3,
    targets=[TargetServer(name="net1.server", host="127.0.0.1", port=21100)],
)
```

Compatibility notes:

- Existing Node examples use richer JSON-like config loaded by
  `loadEntityConfig`.
- Some C++ examples use `targetServerInfo.name_0`, `targetServerInfo.host_0`,
  and `targetServerInfo.port_0`.
- Python can support both target-server styles. For the first milestone, a
  single `entity.server.ip.address` / `entity.server.port.number` target is
  enough.

## Message types to model

The Java Auth library defines the message type IDs. Python should define the
same enum values.

Initial milestone:

- `AUTH_HELLO = 0`
- `ENTITY_HELLO = 1`
- `SESSION_KEY_REQ_IN_PUB_ENC = 20`
- `SESSION_KEY_RESP_WITH_DIST_KEY = 21`
- `SESSION_KEY_REQ = 22`
- `SESSION_KEY_RESP = 23`
- `SKEY_HANDSHAKE_1 = 30`
- `SKEY_HANDSHAKE_2 = 31`
- `SKEY_HANDSHAKE_3 = 32`
- `SECURE_COMM_MSG = 33`
- `FIN_SECURE_COMM = 34`
- `AUTH_ALERT = 100`

Later milestones:

- Auth-to-auth session key request/response messages.
- Delegated access messages.
- Privilege request/response messages.
- Migration messages.
- File-sharing reader messages.
- Secure publish messages.

## Protocol flows

### Session key request

1. Load entity config and credentials.
2. Build a session key request with entity name, Auth ID, requested purpose,
   number of keys, distribution protocol, and crypto spec.
3. If no valid distribution key exists, protect the request using Auth public
   key and entity private key.
4. Send request to Auth over TCP.
5. Receive response.
6. Verify signature or MAC.
7. Decrypt response.
8. Store returned distribution key if included.
9. Store returned session keys in the context key cache.

### Client secure connection

1. Resolve target server host and port.
2. Pick a cached session key or request a new one.
3. Open TCP socket.
4. Send `SKEY_HANDSHAKE_1` with the selected session key ID and nonce.
5. Verify `SKEY_HANDSHAKE_2`.
6. Send `SKEY_HANDSHAKE_3`.
7. Create `SecureChannel`.
8. Send and receive `SECURE_COMM_MSG` frames.

### Server secure connection

1. Listen on configured host and port.
2. Accept TCP socket.
3. Parse `SKEY_HANDSHAKE_1` and read session key ID.
4. Find matching key in cache, or request it from Auth by ID.
5. Send `SKEY_HANDSHAKE_2`.
6. Verify `SKEY_HANDSHAKE_3`.
7. Create `SecureChannel`.
8. Dispatch decrypted application data to callbacks or iterator consumers.

## Crypto choices

Supported session encryption modes should match the C API:

- `AES_128_CBC`
- `AES_128_CTR`
- `AES_128_GCM`

HMAC should be enabled by default for CBC and CTR. GCM can use authenticated
encryption without an additional HMAC when configured that way.

Open implementation choice: use `cryptography` as the Python crypto backend.
It is well maintained and supports RSA, signatures, AES-CBC, AES-CTR, AES-GCM,
HMAC, and secure random byte generation.

## Error model

Create specific exceptions:

- `IoTAuthError`
- `ConfigError`
- `CredentialError`
- `AuthConnectionError`
- `AuthProtocolError`
- `SessionKeyError`
- `SecureHandshakeError`
- `SecureChannelClosed`
- `MessageIntegrityError`
- `InvalidNonceError`
- `InvalidSequenceNumberError`
- `ExpiredKeyError`
- `UnsupportedCryptoError`

The high-level client/server APIs should raise these exceptions. Example apps
can catch `IoTAuthError` for simple demos.

## First milestone

The first useful Python API should include:

- Package scaffold and importable `iotauth` module.
- Config parser for existing C-style `.config` files.
- PEM public/private key loading.
- Message type enum.
- Binary helpers for variable-length integers and fixed-width unsigned ints.
- Session key request over TCP.
- Session key response parsing for the default example crypto settings.
- Session key cache.
- TCP secure client handshake.
- TCP secure server handshake.
- `SecureChannel.send()` and `SecureChannel.recv()`.
- Echo client/server examples.
- Unit tests for config, serialization, crypto helpers, and key cache.
- Integration test against the Java Auth server and C or Node peer.

## Later milestones

- UDP support.
- Permanent distribution key mode.
- Save/load session key cache, optionally password protected.
- Session key request by key ID for server-side handshake misses.
- Auth migration.
- Delegated access and privilege APIs.
- Secure publish/subscribe helpers.
- File-sharing helper APIs.
- Asyncio API:

```python
async with AsyncSecureClient(ctx) as client:
    await client.connect("net1.server")
    await client.send(b"hello")
    data = await client.recv()
```

## Testing strategy

Unit tests:

- Config parser accepts known example configs.
- Config parser rejects missing or malformed required fields.
- Message enum values match Java.
- Integer and buffer serialization round trips.
- Crypto helpers encrypt/decrypt and reject tampered ciphertext.
- Sequence number checks reject replay and out-of-order messages.
- Key cache returns by ID and evicts expired keys.

Integration tests:

- Python client requests a session key from Java Auth.
- Python server accepts a secure connection from C client.
- Python client connects to C or Node server.
- Python client and Python server complete an echo workflow.
- Tampered secure message fails integrity verification.
- Expired session key is rejected.

## Documentation examples to maintain

When implementation begins, keep examples small and runnable:

- `examples/client.py`: connect, send one message, print response.
- `examples/server.py`: accept secure connections and print received data.
- `examples/echo_client.py`: repeated echo client.
- `examples/echo_server.py`: sends received payloads back to sender.
- `examples/configs/client.config`
- `examples/configs/server.config`

## Open questions

- Should the first public API be synchronous only, or should we design the
  object model so an asyncio API can share most internals from day one?
- Should Python expose key IDs as raw bytes, integers, hex strings, or a `KeyId`
  wrapper?
- Which existing config dialect should be treated as canonical for new Python
  examples: C-style properties or Node-style JSON config?
- Do we want Python to interoperate with the current C secure message framing
  first, Node first, or both immediately?
- Should the first implementation require `cryptography`, or should it allow a
  pure-stdlib limited mode for parsing/config tests?
- How much of migration and delegated access should be represented in the first
  set of dataclasses even before the protocol implementation exists?

## Current status

Documentation and API planning only. No new Python implementation has been
added yet.
