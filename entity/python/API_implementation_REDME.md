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

## Step 2: context and credential loading design

After Step 1, Python can read a `.config` file and return validated config
objects. Step 2 should turn that static config into a runtime context. In C,
this job is handled by `init_SST(...)`, which loads config, loads keys, prepares
distribution-key state, and returns an `SST_ctx_t*`.

In Python, the equivalent should be `IoTAuthContext`.

Proposed usage:

```python
from iotauth import IoTAuthContext

ctx = IoTAuthContext.from_config("examples/configs/client.config")
```

At the end of Step 2, `ctx` should not yet talk to Auth or open entity sockets.
It should only prove that the entity has a valid config and usable credentials.

### C mental model

The C API groups runtime state in `SST_ctx_t`:

```c
typedef struct {
    distribution_key_t dist_key;
    config_t config;
    void* pub_key;
    void* priv_key;
    pthread_mutex_t mutex;
} SST_ctx_t;
```

Python should model the same idea with named fields:

```python
@dataclass
class IoTAuthContext:
    config: EntityConfig
    auth_public_key: object
    entity_private_key: object
    distribution_key: DistributionKey | None
    session_keys: SessionKeyCache
```

The `object` type above is temporary documentation language. In the actual
implementation, these should be the public/private key objects returned by the
chosen crypto library.

### Why this comes second

The config parser only answers: "What did the file say?"

The context answers: "Is this entity ready to participate in IoTAuth?"

That means Step 2 should verify:

- The Auth public key file can be loaded.
- The entity private key file can be loaded.
- The key types are acceptable for IoTAuth milestone 1.
- Permanent distribution key mode is either loaded correctly or rejected with a
  clear "not implemented yet" error.
- An empty session key cache exists for later Auth responses.

### Proposed Python modules

Step 2 should add:

```text
entity/python/iotauth/
  context.py
  credentials.py
  keys.py
```

Suggested responsibilities:

- `context.py`
  - Defines `IoTAuthContext`.
  - Provides `IoTAuthContext.from_config(path)`.
  - Calls `load_config(...)`.
  - Calls credential-loading helpers.
  - Creates empty key/cache state.
- `credentials.py`
  - Loads Auth public certificates or public keys from PEM files.
  - Loads entity private keys from PEM files.
  - Converts low-level crypto-library failures into `CredentialError`.
- `keys.py`
  - Defines `DistributionKey`.
  - Defines `SessionKey`.
  - Defines `SessionKeyCache`.

### Proposed public API

```python
ctx = IoTAuthContext.from_config("client.config")

ctx.config.entity.name
ctx.config.auth.host
ctx.auth_public_key
ctx.entity_private_key
ctx.session_keys
```

The public constructor should accept either a path or an already parsed
`EntityConfig`:

```python
ctx = IoTAuthContext.from_config("client.config")
ctx = IoTAuthContext.from_entity_config(config)
```

This keeps tests simple. It also lets future applications generate config in
memory without writing a temporary file.

### Credential loading rules

The current C code expects:

- Auth public credential path: an X.509 PEM certificate.
- Entity private credential path: a PEM private key.
- Auth public key type: RSA.

Python should follow that behavior first.

Credential loader behavior:

- Read Auth public credential from `config.auth.public_key_path`.
- First try to parse it as an X.509 certificate and extract the public key.
- Optionally later support raw PEM public keys.
- Reject non-RSA public keys in milestone 1.
- Read entity private key from `config.entity.private_key_path`.
- Reject encrypted private keys until we explicitly support passphrases.
- Raise `CredentialError` instead of returning `None`.

### Key and cache objects

Step 2 should define the shape of keys even before Auth responses exist.

Proposed `SessionKey` fields:

```python
@dataclass(frozen=True)
class SessionKey:
    id: bytes
    cipher_key: bytes
    mac_key: bytes | None
    abs_validity: int | None
    rel_validity: int | None
    encryption_mode: str
    hmac_enabled: bool
    permanent_distribution_key: bool
```

Proposed `DistributionKey` fields:

```python
@dataclass(frozen=True)
class DistributionKey:
    cipher_key: bytes
    mac_key: bytes | None
    abs_validity: int | None
    encryption_mode: str
```

Proposed `SessionKeyCache` behavior:

- Starts empty.
- Stores keys by 8-byte key ID.
- Rejects duplicate IDs unless explicitly replacing.
- Can find a key by ID.
- Can report whether it has room for more keys.
- Uses `MAX_SESSION_KEY = 10` to match the C API milestone.

### Permanent distribution key mode

C supports permanent distribution keys by loading raw cipher/MAC key files when
`PermanentDistKeyMode` is enabled.

For Python Step 2, recommended behavior:

- If `PermanentDistKeyMode` is disabled, set `distribution_key = None`.
- If `PermanentDistKeyMode` is enabled, either:
  - Load `distKey.cipherkey.path` and `distkey.mackey.path` when both are
    present and have the expected sizes, or
  - Raise `CredentialError("Permanent distribution key mode is not implemented")`
    if we want to defer this feature.

I recommend deferring permanent distribution key support unless we need it
immediately for the first integration test. Normal Auth public/private key mode
is the central path.

### Error model additions

Step 2 should add:

- `CredentialError`: key file exists but cannot be parsed, has the wrong type,
  or is unsupported.
- `KeyCacheError`: invalid key IDs, duplicate keys, or cache capacity problems.

These should inherit from `IoTAuthError`, just like `ConfigError`.

### Tests to add

Unit tests should cover:

- `IoTAuthContext.from_config(...)` loads a valid config and credentials.
- Auth public certificate is parsed and exposes an RSA public key.
- Entity private key is parsed.
- Missing key files still fail clearly.
- Invalid PEM data raises `CredentialError`.
- Encrypted private key raises `CredentialError` until passphrases are
  supported.
- Empty `SessionKeyCache` starts with length `0`.
- `SessionKeyCache` can add and retrieve by key ID.
- `SessionKeyCache` rejects key IDs that are not 8 bytes.
- `SessionKeyCache` enforces the maximum key count.

### Learning notes

Topics worth studying for this step:

- Class methods such as `from_config(...)`: named constructors for objects.
  <https://docs.python.org/3/library/functions.html#classmethod>
- Instance attributes and object state.
  <https://docs.python.org/3/tutorial/classes.html>
- The `cryptography` package X.509 and serialization APIs.
  <https://cryptography.io/en/latest/x509/>
  <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/>
- Python dictionaries as lookup tables, useful for session-key caches.
  <https://docs.python.org/3/tutorial/datastructures.html#dictionaries>

### Step 2 repo references

Python references from Step 1 that Step 2 will build on:

- `entity/python/iotauth/config.py`
  - `load_config(...)`: should be called by `IoTAuthContext.from_config(...)`.
  - `EntityConfig`: should be stored inside `IoTAuthContext`.
- `entity/python/iotauth/exceptions.py`
  - Add `CredentialError` and `KeyCacheError` here.

C references this mirrors:

- `entity/c/src/c_api.h`
  - `SST_ctx_t`: C runtime context containing config, distribution key, public
    key, and private key.
  - `session_key_t`, `distribution_key_t`, and `session_key_list_t`: C key
    objects to mirror with Python dataclasses/cache classes.
  - `init_SST(const char* config_path)`: public C context initializer.
- `entity/c/src/c_api.c`
  - `init_SST(...)`: loads config, loads keys, initializes distribution-key
    state.
  - `init_empty_session_key_list(...)`: creates the empty session-key list.
- `entity/c/src/c_crypto.h`
  - `load_auth_public_key(...)`: Auth public credential loader.
  - `load_entity_private_key(...)`: entity private key loader.
- `entity/c/src/c_crypto.c`
  - `load_auth_public_key(...)`: reads an X.509 PEM cert and extracts an RSA
    public key.
  - `load_entity_private_key(...)`: reads a PEM private key.
  - `load_permanent_distribution_key(...)`: loads raw permanent distribution
    key files.

Expected verification command after implementation:

```sh
PYTHONPATH=entity/python python3 -m unittest discover -s entity/python/tests
```

### Step 2 implementation references

The Step 2 context, credential-loading boundary, and key-cache foundation have
now been implemented.

Python files:

- `entity/python/iotauth/context.py`
  - `IoTAuthContext`: runtime object that holds validated config, loaded
    credentials, distribution-key state, and an empty session-key cache.
  - `IoTAuthContext.from_config(path, validate_paths=True)`: parses config with
    `load_config(...)`, then builds a runtime context.
  - `IoTAuthContext.from_entity_config(config)`: builds a context from an
    already parsed `EntityConfig`, useful for tests and generated configs.
  - Permanent distribution key mode currently raises `CredentialError` so we do
    not silently pretend that path is ready.
- `entity/python/iotauth/credentials.py`
  - `load_auth_public_key(path)`: loads Auth's public credential. It first tries
    X.509 PEM certificate parsing, then raw PEM public key parsing.
  - `load_entity_private_key(path)`: loads the entity PEM private key.
  - `_load_crypto_backend()`: imports the optional `cryptography` package and
    raises `CredentialError` with a clear install message if it is unavailable.
  - Milestone 1 accepts RSA public/private keys only.
- `entity/python/iotauth/keys.py`
  - `SessionKey`: typed session key object with 8-byte key-ID validation.
  - `DistributionKey`: typed distribution-key object.
  - `SessionKeyCache`: in-memory cache keyed by session key ID.
  - `SESSION_KEY_ID_SIZE = 8` and `MAX_SESSION_KEY = 10` mirror the C API.
- `entity/python/iotauth/exceptions.py`
  - Added `CredentialError`.
  - Added `KeyCacheError`.
- `entity/python/iotauth/__init__.py`
  - Exports `IoTAuthContext`, key classes, cache class, and new exceptions.
- `entity/python/tests/test_context.py`
  - Tests context construction from parsed config and config path.
  - Tests that permanent distribution key mode is explicitly deferred.
- `entity/python/tests/test_keys.py`
  - Tests cache start state, add/retrieve, duplicate handling, replace behavior,
    key-ID validation, and cache capacity.
- `entity/python/tests/test_credentials.py`
  - Tests that missing `cryptography` dependency is reported as `CredentialError`.

Dependency note:

- The environment used for this implementation does not currently have the
  `cryptography` package installed.
- The code is structured so context/key/cache behavior can be tested without
  that dependency by patching the credential loaders.
- Real PEM certificate/private-key parsing requires installing `cryptography`
  before using `IoTAuthContext` against actual IoTAuth credentials.

Verification command:

```sh
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 16 tests
OK
```

## Step 3: message types and binary serialization design

After Step 2, Python has a runtime context and key containers, but it still
cannot speak IoTAuth on the wire. Step 3 should add the smallest protocol layer:
message type IDs and binary serialization helpers.

This step should not open sockets, encrypt payloads, or request session keys
yet. It should only answer: "Can Python encode and decode the same basic bytes
that Java, C, and Node expect?"

### C mental model

In C, protocol messages are byte buffers. A sender builds:

```text
message_type: 1 byte
payload_length: variable-length integer
payload: payload_length bytes
```

The C helper `make_sender_buf(...)` creates this frame. The C helper
`parse_received_message(...)` reads the message type and returns a pointer to
the payload.

Python should model this as explicit serialization functions and a tiny frame
object:

```python
@dataclass(frozen=True)
class IoTSPFrame:
    message_type: MessageType
    payload: bytes
```

Suggested usage:

```python
frame = IoTSPFrame(MessageType.SKEY_HANDSHAKE_1, payload)
wire_bytes = serialize_frame(frame)

parsed = parse_frame(wire_bytes)
assert parsed.message_type is MessageType.SKEY_HANDSHAKE_1
assert parsed.payload == payload
```

### Why this comes third

Session key requests and secure handshakes both depend on the same framing
rules. If we get this layer right first, later steps can focus on Auth request
payloads, crypto, and sockets without also debugging byte offsets.

This is the Python version of a C habit you already know well: before writing a
network protocol, define the struct layout and buffer packing rules.

### Proposed Python modules

Step 3 should add:

```text
entity/python/iotauth/
  messages.py
  serialization/
    __init__.py
    binary.py
```

Suggested responsibilities:

- `messages.py`
  - Defines `MessageType` as an `IntEnum`.
  - Defines `IoTSPFrame`.
  - Provides `message_type_from_byte(...)`.
- `serialization/binary.py`
  - Encodes and decodes variable-length integers.
  - Encodes and decodes unsigned big-endian integers.
  - Serializes and parses IoTSP frames.

### MessageType enum

Python should use `enum.IntEnum` so message types behave like integers when
needed, but still have readable names:

```python
class MessageType(IntEnum):
    AUTH_HELLO = 0
    ENTITY_HELLO = 1
    AUTH_SESSION_KEY_REQ = 10
    AUTH_SESSION_KEY_RESP = 11
    SESSION_KEY_REQ_IN_PUB_ENC = 20
    SESSION_KEY_RESP_WITH_DIST_KEY = 21
    SESSION_KEY_REQ = 22
    SESSION_KEY_RESP = 23
    SESSION_KEY_RESP_FOR_DELEGATION = 24
    SESSION_KEY_RESP_FOR_DELEGATION_WITH_DIST_KEY = 25
    SKEY_HANDSHAKE_1 = 30
    SKEY_HANDSHAKE_2 = 31
    SKEY_HANDSHAKE_3 = 32
    SECURE_COMM_MSG = 33
    FIN_SECURE_COMM = 34
    SECURE_PUB = 40
    MIGRATION_REQ_WITH_SIGN = 50
    MIGRATION_RESP_WITH_SIGN = 51
    MIGRATION_REQ_WITH_MAC = 52
    MIGRATION_RESP_WITH_MAC = 53
    ADD_READER_REQ_IN_PUB_ENC = 60
    ADD_READER_RESP_WITH_DIST_KEY = 61
    ADD_READER_REQ = 62
    ADD_READER_RESP = 63
    DELEGATED_ACCESS_REQ_IN_PUB_ENC = 70
    DELEGATED_ACCESS_RESP_WITH_DIST_KEY = 71
    DELEGATED_ACCESS_REQ = 72
    DELEGATED_ACCESS_RESP = 73
    PRIVILEGED_REQ_IN_PUB_ENC = 80
    PRIVILEGED_RESP_WITH_DIST_KEY = 81
    PRIVILEGED_REQ = 82
    PRIVILEGED_RESP = 83
    AUTH_ALERT = 100
```

### Variable-length integer format

IoTAuth uses the same variable-length integer style in Java, C, and Node:

- The integer is encoded 7 bits at a time.
- The low 7 bits go into each byte.
- If more bytes follow, set the high bit (`0x80`).
- The final byte has the high bit clear.
- This is little-endian by 7-bit groups.

Examples:

```text
0      -> 00
1      -> 01
127    -> 7f
128    -> 80 01
300    -> ac 02
```

Python helpers:

```python
encode_varint(300) == b"\xac\x02"
decode_varint(b"\xac\x02", 0) == (300, 2)
```

`decode_varint(...)` should return both the decoded value and the number of
bytes consumed.

### Unsigned big-endian integer helpers

Several IoTAuth fields are fixed-width unsigned integers, including session key
IDs and sequence numbers. Python should provide helpers equivalent to C's
`read_unsigned_int_BE(...)` and Node's `readVariableUIntBE(...)`.

```python
encode_uint_be(value=5, length=8) == b"\x00\x00\x00\x00\x00\x00\x00\x05"
decode_uint_be(b"\x00\x00\x00\x00\x00\x00\x00\x05") == 5
```

Validation:

- Reject negative values.
- Reject values too large for the requested byte length.
- Reject empty byte lengths.

### IoTSP frame format

The frame format should match Java `IoTSPMessage`, Node `serializeIoTSP(...)`,
and C `make_sender_buf(...)`:

```text
offset  size       field
0       1 byte     message type
1       varint     payload length
...     N bytes    payload
```

Python helpers:

```python
serialize_frame(IoTSPFrame(MessageType.SECURE_COMM_MSG, b"abc"))
parse_frame(data)
```

Parsing validation:

- Reject empty buffers.
- Reject unknown message types.
- Reject truncated variable-length integers.
- Reject frames whose declared payload length exceeds available bytes.
- Reject frames with trailing bytes unless the parser explicitly allows them.

### Error model additions

Step 3 should add:

- `SerializationError`: invalid integer encoding, truncated frame, unknown
  message type, malformed payload length.

This should inherit from `IoTAuthError`.

### Tests to add

Unit tests should cover:

- Every `MessageType` value matches Java and Node.
- Known varint examples: `0`, `1`, `127`, `128`, `300`.
- Varint rejects negative numbers.
- Varint rejects truncated encodings.
- Big-endian integer helpers round trip 1-, 2-, 4-, and 8-byte values.
- Big-endian helper rejects values too large for the requested length.
- IoTSP frame serialization produces expected bytes.
- IoTSP frame parsing round trips message type and payload.
- Frame parser rejects unknown message type.
- Frame parser rejects payload length mismatch.
- Frame parser rejects trailing bytes by default.

### Learning notes

Topics worth studying for this step:

- `enum.IntEnum`: named constants that still behave like integers.
  <https://docs.python.org/3/library/enum.html#enum.IntEnum>
- Python `bytes` and `bytearray`: immutable vs mutable byte buffers.
  <https://docs.python.org/3/library/stdtypes.html#bytes-objects>
- `int.to_bytes(...)` and `int.from_bytes(...)`: Python's built-in way to pack
  and unpack fixed-width integers.
  <https://docs.python.org/3/library/stdtypes.html#int.to_bytes>
- Binary protocols generally: keep parsing strict and fail early on malformed
  buffers.

### Step 3 repo references

Python references from previous steps that Step 3 will build on:

- `entity/python/iotauth/exceptions.py`
  - Add `SerializationError` here.
- `entity/python/iotauth/__init__.py`
  - Export `MessageType`, `IoTSPFrame`, and common serialization helpers if they
    are intended as public API.

Java references:

- `auth/library/src/main/java/org/iot/auth/message/MessageType.java`
  - Canonical message type values.
- `auth/library/src/main/java/org/iot/auth/message/IoTSPMessage.java`
  - Java IoTSP frame format: message type, variable-length payload length,
    payload.
- `auth/library/src/main/java/org/iot/auth/io/VariableLengthInt.java`
  - Java variable-length integer implementation.

C references:

- `entity/c/src/c_common.c`
  - `num_to_var_length_int(...)`: C varint encoder.
  - `var_length_int_to_num(...)`: C varint decoder.
  - `read_unsigned_int_BE(...)`: C big-endian integer reader.
  - `make_sender_buf(...)`: C IoTSP frame serializer.
  - `parse_received_message(...)`: C IoTSP frame parser.
- `entity/c/src/c_common.h`
  - Function declarations for the same helpers.

Node references:

- `entity/node/accessors/node_modules/common.js`
  - `msgType`: Node message type values.
  - `numToVarLenInt(...)` and `varLenIntToNum(...)`: Node varint helpers.
  - `readVariableUIntBE(...)` and `writeVariableUIntBE(...)`: Node fixed-width
    integer helpers.
  - `serializeIoTSP(...)` and `parseIoTSP(...)`: Node frame helpers.

Expected verification command after implementation:

```sh
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s entity/python/tests
```

### Step 3 implementation references

The Step 3 message-type and binary-serialization layer has now been
implemented.

Python files:

- `entity/python/iotauth/messages.py`
  - `MessageType`: Python `IntEnum` containing the IoTAuth protocol message IDs
    from Java and Node.
  - `IoTSPFrame`: small immutable frame object with `message_type` and
    `payload`.
  - `message_type_from_byte(...)`: validates raw message type bytes and raises
    `SerializationError` for unknown values.
- `entity/python/iotauth/serialization/binary.py`
  - `encode_varint(...)`: encodes IoTAuth variable-length integers.
  - `decode_varint(...)`: decodes IoTAuth variable-length integers and returns
    `(value, bytes_consumed)`.
  - `encode_uint_be(...)`: encodes fixed-width unsigned big-endian integers.
  - `decode_uint_be(...)`: decodes fixed-width unsigned big-endian integers.
  - `serialize_frame(...)`: serializes an `IoTSPFrame` as message type,
    varint payload length, and payload bytes.
  - `parse_frame(...)`: parses IoTSP frame bytes and rejects malformed frames.
- `entity/python/iotauth/serialization/__init__.py`
  - Exports the binary serialization helpers.
- `entity/python/iotauth/exceptions.py`
  - Added `SerializationError`.
- `entity/python/iotauth/__init__.py`
  - Exports `MessageType`, `IoTSPFrame`, `message_type_from_byte(...)`, and the
    serialization helpers.
- `entity/python/tests/test_messages.py`
  - Tests message type values and unknown message type rejection.
- `entity/python/tests/test_serialization.py`
  - Tests varint encoding/decoding, unsigned big-endian helpers, IoTSP frame
    serialization/parsing, and malformed-frame rejection.

Implementation notes:

- The varint helpers match the Java/C/Node 7-bit continuation-byte format.
- The parser is strict by default: unknown message types, truncated varints,
  payload length mismatches, and trailing bytes raise `SerializationError`.
- `parse_frame(..., allow_trailing=True)` exists for future stream-buffer use
  cases where one read may contain more than one frame.
- The helpers do not perform crypto, socket I/O, or Auth request construction.
  Those are intentionally later steps.

Verification command:

```sh
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 33 tests
OK
```

## Step 4: Auth session-key message design

After Step 3, Python can encode and decode generic IoTSP frames:

```text
message_type: 1 byte
payload_length: variable-length integer
payload: payload_length bytes
```

Step 4 should move one layer up. It should define the payload objects used when
an entity talks to Auth for session keys.

This step should not open sockets yet. It should not encrypt, decrypt, sign, or
verify payloads yet. It should only build and parse the cleartext payload
structures that later crypto and transport code will wrap.

### Why this comes next

The first real Auth workflow will be:

1. Receive `AUTH_HELLO` from Auth.
2. Parse Auth ID and Auth nonce.
3. Generate an entity nonce.
4. Build a session-key request payload.
5. Encrypt/sign or MAC-protect that payload.
6. Wrap it in an IoTSP frame.
7. Send it over TCP.
8. Receive a session-key response.
9. Decrypt/verify the response.
10. Parse returned distribution/session keys.

Step 4 covers only the payload-building and payload-parsing pieces from that
workflow. This keeps byte layout work separate from crypto and sockets.

### C mental model

In C, this layer is mostly raw buffers and helper functions:

```c
serialize_message_for_auth(...)
handle_AUTH_HELLO(...)
parse_session_key_response(...)
parse_distribution_key(...)
parse_session_key(...)
```

Python should represent those payloads as small typed objects with explicit
serialization helpers.

Suggested shape:

```python
@dataclass(frozen=True)
class AuthHelloPayload:
    auth_id: int
    nonce: bytes


@dataclass(frozen=True)
class SessionKeyRequestPayload:
    entity_nonce: bytes
    auth_nonce: bytes
    num_keys: int
    entity_name: str
    purpose: dict[str, object] | str
    diffie_hellman_param: bytes | None = None
```

### Proposed Python module

Step 4 should add:

```text
entity/python/iotauth/auth_messages.py
```

Suggested responsibilities:

- Parse `AUTH_HELLO` payloads.
- Parse `AUTH_ALERT` payloads.
- Serialize session-key request payloads.
- Parse cleartext session-key response payloads after a future crypto layer has
  decrypted them.
- Parse distribution-key and session-key binary records.

### Constants

Step 4 should define these protocol sizes:

```python
AUTH_ID_SIZE = 4
NONCE_SIZE = 8
SESSION_KEY_ID_SIZE = 8
DIST_KEY_EXPIRATION_TIME_SIZE = 6
KEY_EXPIRATION_TIME_SIZE = 6
REL_VALIDITY_SIZE = 6
MAC_KEY_SIZE = 32
AES_128_KEY_SIZE = 16
```

Some constants already exist in the C API. Python should keep names close
enough that cross-referencing C and Python stays easy.

### AuthHello payload

`AUTH_HELLO` frame payload format:

```text
offset  size       field
0       4 bytes    auth_id, unsigned big-endian
4       8 bytes    auth_nonce
```

Python API:

```python
payload = parse_auth_hello_payload(frame.payload)
payload.auth_id
payload.nonce
```

Validation:

- Payload length must be exactly `12` bytes.
- Auth nonce must be exactly `8` bytes.
- The caller should compare `payload.auth_id` with `ctx.config.auth.id`.

### AuthAlert payload

`AUTH_ALERT` frame payload format:

```text
offset  size       field
0       1 byte     alert_code
```

Python API:

```python
alert = parse_auth_alert_payload(frame.payload)
alert.code
```

This gives future Auth workflows a clean way to fail with an Auth-provided
reason instead of treating every failure as malformed bytes.

### Buffered string format

Java and Node use a "buffered string" format:

```text
string_length: variable-length integer
string_bytes: UTF-8 bytes
```

Python helpers:

```python
serialize_buffered_string("net1.client")
parse_buffered_string(data, offset) -> (value, bytes_consumed)
```

These helpers are needed for:

- Entity names.
- JSON purpose strings.
- Crypto-spec JSON strings in session-key responses.
- Future delegation/migration strings.

Validation:

- Reject truncated length fields.
- Reject string length larger than available bytes.
- Decode as UTF-8.
- Return consumed byte count so parsers can advance correctly.

### Session-key request payload

Cleartext `SessionKeyReq` payload format:

```text
offset  size       field
0       8 bytes    entity_nonce
8       8 bytes    auth_nonce
16      4 bytes    num_keys, unsigned big-endian
20      varstr     entity_name
...     varstr     purpose JSON string
...     optional   Diffie-Hellman parameter bytes
```

Python API:

```python
request = SessionKeyRequestPayload(
    entity_nonce=entity_nonce,
    auth_nonce=auth_nonce,
    num_keys=ctx.config.num_keys,
    entity_name=ctx.config.entity.name,
    purpose={"group": "Servers"},
)

payload = serialize_session_key_request_payload(request)
```

Purpose serialization rule:

- If `purpose` is a dictionary, serialize with compact JSON using stable key
  ordering.
- If `purpose` is already a string, preserve it exactly.

The string-preserving path matters because existing configs sometimes use
purpose strings like:

```properties
entityInfo.purpose={"keyId":00000000}
```

That is not strict JSON, but existing C-style examples may still rely on it.

### Session-key response payload

Step 4 should parse only the cleartext/decrypted response payload. It should not
decrypt the response yet.

Cleartext `SessionKeyResp` inner payload format:

```text
offset  size       field
0       8 bytes    entity_nonce
8       varstr     crypto spec JSON string
...     4 bytes    session key count, unsigned big-endian
...     repeated   session key records
```

Response frames that include a new distribution key have an encrypted
distribution-key prefix before the encrypted response body. That outer
encryption/signature handling belongs in a later crypto/Auth-service step.

Python API:

```python
response = parse_session_key_response_payload(decrypted_payload)
response.entity_nonce
response.crypto_spec
response.session_keys
```

Validation:

- Entity nonce must be exactly `8` bytes.
- Crypto spec must be a buffered string.
- Session key count must fit available data.
- Parser must reject trailing bytes unless explicitly allowed.

### Distribution-key record

Distribution key binary record format:

```text
offset  size       field
0       6 bytes    absolute validity, unsigned big-endian
6       1 byte     cipher key size
7       variable   cipher key bytes
...     1 byte     MAC key size
...     variable   MAC key bytes
```

Python API:

```python
distribution_key = parse_distribution_key_record(data)
```

This should return the `DistributionKey` dataclass introduced in Step 2.

### Session-key record

Session key binary record format:

```text
offset  size       field
0       8 bytes    key ID
8       6 bytes    absolute validity, unsigned big-endian
14      6 bytes    relative validity, unsigned big-endian
20      1 byte     cipher key size
21      variable   cipher key bytes
...     1 byte     MAC key size
...     variable   MAC key bytes
```

Python API:

```python
session_key, consumed = parse_session_key_record(data, offset, session_config)
```

The parser should use the active config/session crypto settings to populate:

- `encryption_mode`
- `hmac_enabled`
- `permanent_distribution_key`

This mirrors the C helper that updates parsed session keys with config modes.

### Error model additions

Step 4 can reuse `SerializationError` for malformed byte payloads.

It may also add:

- `AuthProtocolError`: valid bytes but invalid Auth protocol state, such as an
  unexpected Auth ID.

Recommended split:

- Use `SerializationError` for malformed payload structure.
- Use `AuthProtocolError` for semantically valid payloads that do not match the
  current entity context.

### Tests to add

Unit tests should cover:

- `parse_auth_hello_payload(...)` accepts a 12-byte payload.
- `parse_auth_hello_payload(...)` rejects short or long payloads.
- `parse_auth_alert_payload(...)` parses one-byte alert codes.
- Buffered string serialization and parsing round trip ASCII and UTF-8.
- Buffered string parser rejects truncated data.
- Session-key request serialization matches known byte layout.
- Dictionary purpose serializes to compact JSON.
- Raw string purpose is preserved.
- Session-key response parser handles one cleartext session-key record.
- Session-key response parser rejects count/payload mismatch.
- Distribution-key parser handles cipher/MAC key sizes.
- Session-key parser rejects invalid key ID length or truncated key material.

### Learning notes

Topics worth studying for this step:

- JSON serialization with `json.dumps(...)`.
  <https://docs.python.org/3/library/json.html#json.dumps>
- UTF-8 string encoding and decoding in Python.
  <https://docs.python.org/3/howto/unicode.html>
- Dataclasses with methods: small typed payload objects that know how to
  validate themselves.
  <https://docs.python.org/3/library/dataclasses.html>
- Binary parser design: always track offsets and consumed byte counts.

### Step 4 repo references

Python references from previous steps that Step 4 will build on:

- `entity/python/iotauth/messages.py`
  - `MessageType.AUTH_HELLO`
  - `MessageType.AUTH_ALERT`
  - `MessageType.SESSION_KEY_REQ_IN_PUB_ENC`
  - `MessageType.SESSION_KEY_REQ`
- `entity/python/iotauth/serialization/binary.py`
  - `encode_varint(...)`
  - `decode_varint(...)`
  - `encode_uint_be(...)`
  - `decode_uint_be(...)`
  - `serialize_frame(...)`
  - `parse_frame(...)`
- `entity/python/iotauth/keys.py`
  - `DistributionKey`
  - `SessionKey`
- `entity/python/iotauth/exceptions.py`
  - `SerializationError`
  - Add `AuthProtocolError` here if needed.

Java references:

- `auth/library/src/main/java/org/iot/auth/message/AuthHelloMessage.java`
  - Auth hello payload: Auth ID plus Auth nonce.
- `auth/library/src/main/java/org/iot/auth/message/SessionKeyReqMessage.java`
  - Session-key request payload parser and field order.
- `auth/library/src/main/java/org/iot/auth/message/SessionKeyRespMessage.java`
  - Session-key response payload serializer and field order.
- `auth/library/src/main/java/org/iot/auth/io/BufferedString.java`
  - Buffered string format.
- `auth/library/src/main/java/org/iot/auth/crypto/SessionKey.java`
  - Java session-key record serialization.
- `auth/library/src/main/java/org/iot/auth/crypto/DistributionKey.java`
  - Java distribution-key record serialization.

C references:

- `entity/c/src/c_secure_comm.c`
  - `handle_AUTH_HELLO(...)`: parses Auth hello, generates entity nonce, builds
    request.
  - `serialize_session_key_req_with_distribution_key(...)`: wraps an encrypted
    request with sender identity when a distribution key is already valid.
  - `parse_string_param(...)`: parses buffered strings.
  - `parse_session_key_response(...)`: parses decrypted session-key responses.
  - `parse_distribution_key(...)`: parses distribution-key records.
  - `parse_session_key(...)`: parses session-key records.

Node references:

- `entity/node/accessors/node_modules/iotAuthService.js`
  - `serializeAuthHello(...)` and `parseAuthHello(...)`.
  - `serializeSessionKeyReq(...)`.
  - `parseDistributionKey(...)`.
  - Session-key response parsing helpers nearby.
- `entity/node/accessors/node_modules/common.js`
  - `serializeStringParam(...)` and `parseStringParam(...)`.

Expected verification command after implementation:

```sh
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s entity/python/tests
```

### Step 4 implementation references

The Step 4 Auth-facing payload layer has now been implemented.

Python files:

- `entity/python/iotauth/auth_messages.py`
  - `AuthHelloPayload`: parsed `AUTH_HELLO` payload object.
  - `AuthAlertPayload`: parsed `AUTH_ALERT` payload object.
  - `SessionKeyRequestPayload`: cleartext session-key request payload object.
  - `SessionKeyResponsePayload`: cleartext/decrypted session-key response object.
  - `parse_auth_hello_payload(...)`: parses Auth ID and Auth nonce.
  - `parse_auth_alert_payload(...)`: parses one-byte Auth alert codes.
  - `serialize_buffered_string(...)`: serializes Java/Node-style buffered
    strings.
  - `parse_buffered_string(...)`: parses buffered strings and returns
    `(value, bytes_consumed)`.
  - `serialize_session_key_request_payload(...)`: serializes the cleartext
    session-key request payload.
  - `parse_session_key_response_payload(...)`: parses a decrypted session-key
    response payload into session key objects.
  - `parse_distribution_key_record(...)`: parses distribution-key records into
    `DistributionKey`.
  - `parse_session_key_record(...)`: parses one session-key record and returns
    `(SessionKey, bytes_consumed)`.
- `entity/python/iotauth/exceptions.py`
  - Added `AuthProtocolError` for future semantic Auth protocol failures.
  - Step 4 malformed bytes currently raise `SerializationError`.
- `entity/python/iotauth/__init__.py`
  - Exports Step 4 payload classes, constants, and helper functions.
- `entity/python/tests/test_auth_messages.py`
  - Tests Auth hello/alert parsing, buffered strings, session-key request
    serialization, distribution/session key records, and cleartext response
    parsing.

Implementation notes:

- Step 4 does not perform socket I/O.
- Step 4 does not encrypt, decrypt, sign, verify, or MAC payloads.
- Dictionary purposes serialize as compact stable JSON, for example
  `{"group":"Servers"}`.
- Raw purpose strings are preserved exactly for compatibility with existing
  config values such as `{"keyId":00000000}`.
- Session-key records are converted into the Step 2 `SessionKey` dataclass using
  the active `SessionConfig`.

Verification command:

```sh
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 48 tests
OK
```

## Step 5: crypto layer design

After Step 4, Python can build and parse the cleartext Auth payloads, but those
payloads are not safe to send yet. Step 5 should add the cryptographic
operations that protect those payloads before they are wrapped in IoTSP frames
and sent over TCP.

This step should not open sockets and should not implement the full Auth
request workflow yet. It should only provide tested crypto primitives and
higher-level wrappers that later Auth-service code can call.

### Why this comes next

The session-key request path has two protection modes:

1. No valid distribution key yet:
   - Encrypt the cleartext request payload with Auth's public key.
   - Sign the encrypted bytes with the entity private key.
   - Send as `SESSION_KEY_REQ_IN_PUB_ENC`.
2. Valid distribution key already exists:
   - Symmetrically encrypt/authenticate the cleartext request payload with the
     distribution key.
   - Prefix the sender entity name.
   - Send as `SESSION_KEY_REQ`.

The session-key response path also needs crypto:

- Verify Auth's signature on a new encrypted distribution key.
- Decrypt the distribution key with the entity private key.
- Decrypt/authenticate the session-key response body with the distribution key.

Step 5 provides these building blocks, but leaves socket sequencing for Step 6.

### C mental model

In C, the crypto layer is mostly in `c_crypto.c`, with Auth-specific wrapping in
`c_secure_comm.c`:

```c
public_encrypt(...)
private_decrypt(...)
SHA256_sign(...)
SHA256_verify(...)
symmetric_encrypt_authenticate(...)
symmetric_decrypt_authenticate(...)
encrypt_and_sign(...)
save_distribution_key(...)
```

Python should mirror this with small explicit functions instead of hiding
everything inside the future `AuthService`.

### Proposed Python modules

Step 5 should add:

```text
entity/python/iotauth/
  crypto.py
```

Suggested responsibilities:

- RSA/OAEP public-key encryption.
- RSA/OAEP private-key decryption.
- RSA/SHA-256 signing.
- RSA/SHA-256 verification.
- AES-128-CBC encryption/decryption.
- AES-128-CTR encryption/decryption.
- AES-128-GCM encryption/decryption.
- HMAC-SHA256 attach/verify helpers.
- IoTAuth symmetric encrypt/authenticate envelope helpers.
- Auth-specific public-encrypt-and-sign wrapper.
- Auth-specific verify-and-private-decrypt wrapper.

### Dependency

Step 5 should use the `cryptography` package.

The current `credentials.py` module already treats `cryptography` as the real
PEM parsing dependency. Step 5 should make that dependency explicit for crypto
operations too.

Implementation rule:

- If `cryptography` is missing, raise `CredentialError` or
  `UnsupportedCryptoError` with a clear install message.
- Do not silently fall back to weak or home-grown crypto.

### Public-key crypto API

Proposed helpers:

```python
public_encrypt(payload: bytes, public_key) -> bytes
private_decrypt(ciphertext: bytes, private_key) -> bytes
sign_sha256(data: bytes, private_key) -> bytes
verify_sha256(data: bytes, signature: bytes, public_key) -> None
```

Expected algorithms:

- RSA encryption padding: OAEP.
- OAEP hash: SHA-256 if compatible with Auth, otherwise SHA-1 may be needed for
  compatibility with existing Java/C behavior. This must be verified before
  implementation.
- Signature hash: SHA-256.
- Signature padding: PKCS#1 v1.5 if matching existing C `RSA_PKCS1_PADDING`.

Open compatibility decision:

- C uses `RSA_PKCS1_OAEP_PADDING` for encryption/decryption.
- C uses `RSA_PKCS1_PADDING` with SHA-256 for signatures.
- Python should match the C/Auth server behavior exactly, even if a newer
  default would be different.

### Public encrypt and sign envelope

When no valid distribution key exists, the entity sends a request protected by
Auth public key and entity private key.

C helper:

```c
encrypt_and_sign(...)
```

Python helper:

```python
encrypt_and_sign_for_auth(payload: bytes, ctx: IoTAuthContext) -> bytes
```

Expected output format:

```text
encrypted_payload: RSA_KEY_SIZE bytes
signature: RSA_KEY_SIZE bytes
```

For the current RSA-2048 credentials, that means:

```text
encrypted payload: 256 bytes
signature: 256 bytes
total: 512 bytes
```

Validation:

- Reject payloads too large for RSA/OAEP direct encryption.
- Confirm key type and key size.
- Raise `UnsupportedCryptoError` for unsupported key types.

Important future concern:

- RSA can only encrypt small payloads directly. If session-key request payloads
  grow, we may need hybrid encryption. For now, match the current IoTAuth
  protocol.

### Verify and decrypt distribution key

When Auth returns a new distribution key, Python needs the reverse operation:

```python
verify_and_decrypt_from_auth(
    signed_ciphertext: bytes,
    ctx: IoTAuthContext,
    encrypted_size: int,
) -> bytes
```

Expected behavior:

1. Split `signed_ciphertext` into encrypted data and signature.
2. Verify the signature using Auth's public key.
3. Decrypt the encrypted data using the entity private key.
4. Return the decrypted distribution-key record bytes.

The parser from Step 4 can then convert those bytes into `DistributionKey`.

### Symmetric envelope format

The C symmetric helpers produce an envelope broadly shaped like:

```text
iv: variable size based on AES mode
ciphertext: encrypted payload
hmac_tag: optional, usually 32 bytes for HMAC-SHA256
```

For AES-GCM, the authentication tag is part of the AEAD mode. The C code uses a
GCM tag size of 12 bytes.

Python helpers:

```python
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
```

Validation:

- AES-128 keys must be exactly 16 bytes.
- HMAC-SHA256 keys should be 32 bytes when HMAC is enabled.
- CBC IV should be 16 bytes.
- CTR IV should be 16 bytes.
- GCM IV should be 12 bytes.
- Reject unsupported encryption modes.
- Verify HMAC before decrypting for CBC/CTR.
- Reject tampered envelopes.

### Distribution-key request wrapper

When a valid distribution key exists, C wraps the encrypted request with the
sender name:

```text
sender_name_length: 1 byte
sender_name: sender_name_length bytes
encrypted_authenticated_payload: remaining bytes
```

Python helper:

```python
encrypt_request_with_distribution_key(
    payload: bytes,
    sender_name: str,
    distribution_key: DistributionKey,
) -> bytes
```

This should mirror C's `serialize_session_key_req_with_distribution_key(...)`.

Open issue:

- This C helper uses a one-byte sender length, unlike the buffered string helper
  used elsewhere. Python should match C here for compatibility.

### Error model additions

Step 5 should add:

- `UnsupportedCryptoError`: unsupported cipher mode, key type, key size, padding
  mode, or missing crypto backend.
- `MessageIntegrityError`: signature verification, HMAC verification, or AEAD
  tag verification failed.

These should inherit from `IoTAuthError`.

Suggested split:

- Use `UnsupportedCryptoError` when the operation cannot be attempted safely.
- Use `MessageIntegrityError` when protected bytes fail verification.
- Use `SerializationError` only when a binary envelope is malformed.

### Tests to add

Unit tests should cover:

- RSA encrypt/decrypt round trip using generated test keys.
- RSA signature verify succeeds for original bytes.
- RSA signature verify fails for tampered bytes.
- Public encrypt and sign envelope splits into encrypted bytes and signature.
- Verify and decrypt rejects tampered signature.
- AES-128-CBC encrypt/decrypt round trip.
- AES-128-CTR encrypt/decrypt round trip.
- AES-128-GCM encrypt/decrypt round trip.
- HMAC-SHA256 detects tampered ciphertext.
- Symmetric decrypt rejects malformed envelopes.
- Unsupported encryption mode raises `UnsupportedCryptoError`.
- Wrong AES key length raises `UnsupportedCryptoError`.
- Distribution-key request wrapper preserves one-byte sender-name prefix.

Integration-style tests, once `cryptography` is installed:

- Load existing IoTAuth example credentials.
- Encrypt/sign a Step 4 session-key request payload.
- Verify/decrypt using the corresponding test key pair.

### Learning notes

Topics worth studying for this step:

- `cryptography` RSA encryption and padding:
  <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/>
- `cryptography` signatures:
  <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing>
- `cryptography` symmetric encryption:
  <https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/>
- HMAC:
  <https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/>
- Why authentication must be verified before trusting decrypted data.

### Step 5 repo references

Python references from previous steps that Step 5 will build on:

- `entity/python/iotauth/context.py`
  - `IoTAuthContext`: provides loaded Auth public key, entity private key, and
    distribution key state.
- `entity/python/iotauth/credentials.py`
  - Existing `cryptography` backend loading pattern.
- `entity/python/iotauth/auth_messages.py`
  - Step 4 cleartext request/response payload bytes.
- `entity/python/iotauth/keys.py`
  - `DistributionKey`
  - `SessionKey`
- `entity/python/iotauth/exceptions.py`
  - Add `UnsupportedCryptoError`.
  - Add `MessageIntegrityError`.

C references:

- `entity/c/src/c_crypto.h`
  - `public_encrypt(...)`
  - `private_decrypt(...)`
  - `SHA256_sign(...)`
  - `SHA256_verify(...)`
  - `symmetric_encrypt_authenticate(...)`
  - `symmetric_decrypt_authenticate(...)`
- `entity/c/src/c_crypto.c`
  - RSA encryption/decryption implementation.
  - RSA/SHA-256 signing and verification.
  - AES mode selection.
  - HMAC-SHA256 attach/verify behavior.
- `entity/c/src/c_secure_comm.c`
  - `encrypt_and_sign(...)`
  - `serialize_session_key_req_with_distribution_key(...)`
  - `save_distribution_key(...)`
  - Symmetric decrypt path for session-key responses.
- `entity/c/src/c_api.h`
  - AES mode enum values and key size constants.

Java references:

- `auth/library/src/main/java/org/iot/auth/crypto/AuthCrypto.java`
  - Auth-side public/private and symmetric crypto helpers.
- `auth/library/src/main/java/org/iot/auth/crypto/SymmetricKey.java`
  - Java symmetric key encrypt/authenticate behavior.
- `auth/library/src/main/java/org/iot/auth/crypto/DistributionKey.java`
  - Distribution-key representation.
- `auth/library/src/main/java/org/iot/auth/crypto/SessionKey.java`
  - Session-key representation.

Node references:

- `entity/node/accessors/node_modules/common.js`
  - `publicEncryptAndSign(...)`
  - `privateDecrypt(...)`
  - `signAndAttach(...)`
  - `verifySignedData(...)`
  - `symmetricEncryptAuthenticate(...)`
  - `symmetricDecryptAuthenticate(...)`
- `entity/node/accessors/node_modules/iotAuthService.js`
  - Session-key request and response crypto flow.

Expected verification command after implementation:

```sh
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s entity/python/tests
```

### Step 5 implementation references

The Step 5 crypto helper layer has now been implemented.

Python files:

- `entity/python/iotauth/crypto.py`
  - `public_encrypt(...)`: RSA/OAEP public-key encryption.
  - `private_decrypt(...)`: RSA/OAEP private-key decryption.
  - `sign_sha256(...)`: RSA/SHA-256 signing with PKCS#1 v1.5 signature padding.
  - `verify_sha256(...)`: RSA/SHA-256 signature verification.
  - `encrypt_and_sign_for_auth(...)`: Auth request public-encrypt-and-sign
    envelope for the no-distribution-key path.
  - `verify_and_decrypt_from_auth(...)`: verifies Auth signature, then decrypts
    with the entity private key.
  - `symmetric_encrypt_authenticate(...)`: AES envelope encryption with optional
    HMAC-SHA256.
  - `symmetric_decrypt_authenticate(...)`: HMAC verification and AES envelope
    decryption.
  - `encrypt_request_with_distribution_key(...)`: mirrors the C sender-name
    prefix plus distribution-key protected payload format.
  - `decrypt_request_with_distribution_key(...)`: parses that sender-name
    prefix and decrypts the protected payload.
- `entity/python/iotauth/exceptions.py`
  - Added `UnsupportedCryptoError`.
  - Added `MessageIntegrityError`.
- `entity/python/iotauth/__init__.py`
  - Exports Step 5 crypto helpers and new exceptions.
- `entity/python/tests/test_crypto.py`
  - Tests clear missing-dependency errors.
  - Tests sender-name validation for the distribution-key wrapper.
  - Includes real RSA/AES/HMAC round-trip tests that run when `cryptography` is
    installed and skip otherwise.

Implementation notes:

- Real crypto operations require the `cryptography` package.
- This environment does not currently have `cryptography` installed, so the
  real RSA/AES/HMAC round-trip tests are skipped locally.
- RSA encryption uses OAEP with SHA-1 to match OpenSSL's default
  `RSA_PKCS1_OAEP_PADDING` behavior in the existing C implementation.
- RSA signatures use PKCS#1 v1.5 with SHA-256 to match the C
  `SHA256_sign(...)` / `SHA256_verify(...)` path.
- Symmetric envelopes use `IV + ciphertext + optional HMAC`.
- AES-GCM uses a 12-byte IV and stores a 12-byte authentication tag for C
  compatibility.
- CBC/CTR HMAC verification is performed before decryption.
- Step 5 still does not perform socket I/O or the full Auth request workflow.

Verification command:

```sh
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s entity/python/tests
```

Current result in this environment:

```text
Ran 60 tests
OK (skipped=10)
```

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

Steps 1 through 10 now have implementation and tests. The API is still growing
step by step, so the sections above should be treated as both design notes and
learning notes for the current implementation.

## Local Python virtual environment

A Python virtual environment is a private copy of the Python package
environment for this project. It is similar in spirit to keeping project-local
build output separate from system-wide C libraries: we can install packages for
IoTAuth without changing the machine's global Python setup.

For this repository, the virtual environment lives at:

```text
entity/python/.venv
```

That directory is intentionally ignored by the root `.gitignore`, because it is
generated local state. We commit the source code and documentation, not the
installed package files inside `.venv`.

Create the environment from the repository root:

```bash
cd /Users/krutyanjayshinde/Desktop/OPT_project/iotauth
python3 -m venv entity/python/.venv
```

Activate it before working on the Python API:

```bash
source entity/python/.venv/bin/activate
```

After activation, the `python` and `pip` commands point at the project-local
environment instead of the global Python installation.

Install the dependency needed by the credential and crypto steps:

```bash
python -m pip install --upgrade pip
python -m pip install cryptography
```

Run the current unit tests through the virtual environment:

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s entity/python/tests
```

Why these command pieces matter:

- `PYTHONPATH=entity/python` tells Python where to find the local `iotauth`
  package before it is formally packaged and installed.
- `PYTHONDONTWRITEBYTECODE=1` keeps Python from creating `__pycache__`
  directories while we are still doing early development.
- `python -m unittest discover -s entity/python/tests` runs every test module in
  the current test directory.

When you are done working, leave the virtual environment:

```bash
deactivate
```

Implementation references:

- Root ignore rules for the virtual environment:
  `/Users/krutyanjayshinde/Desktop/OPT_project/iotauth/.gitignore`
- Virtual environment location:
  `/Users/krutyanjayshinde/Desktop/OPT_project/iotauth/entity/python/.venv`
- Current test command:
  `PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests`

## Step 6: Auth TCP session-key service design

After Step 5, Python has all the pieces needed to protect Auth messages:

- Step 1 loads and validates config.
- Step 2 loads credentials and creates `IoTAuthContext`.
- Step 3 frames messages as IoTSP frames.
- Step 4 builds and parses Auth session-key payloads.
- Step 5 encrypts, signs, verifies, decrypts, and MAC-checks protected bytes.

Step 6 should connect those pieces into the first real network workflow:
requesting session keys from Auth over TCP.

This step should still not implement entity-to-entity secure channels. It should
only talk to Auth, request session keys, validate Auth's response, and store the
returned session keys in the context cache.

### Goal

At the end of Step 6, application code should be able to do this:

```python
from iotauth import IoTAuthContext, request_session_keys

ctx = IoTAuthContext.from_config("entity/python/examples/configs/client.config")
keys = request_session_keys(ctx)
```

Or, if we decide to put the method directly on the context:

```python
ctx = IoTAuthContext.from_config("entity/python/examples/configs/client.config")
keys = ctx.request_session_keys()
```

Recommended first implementation: keep the workflow in an `auth_service.py`
function first. Once the behavior is stable, `IoTAuthContext.request_session_keys`
can delegate to that function.

### Why this comes next

This is the first step where the Python API becomes useful against a running
Auth server.

So far, most of the work has been local and deterministic:

- Parse files.
- Load keys.
- Encode bytes.
- Decode bytes.
- Encrypt and decrypt bytes.

Step 6 adds I/O. That means Python must now handle the same kinds of failures a
C socket caller handles:

- Auth is not listening.
- The TCP connection closes early.
- A message arrives in multiple TCP reads.
- Auth sends a valid frame with the wrong message type.
- Auth returns `AUTH_ALERT`.
- Auth's nonce response does not match the entity nonce.
- Auth returns a session key response that fails crypto verification.

### C mental model

The C flow lives mostly in `entity/c/src/c_secure_comm.c`:

```c
send_session_key_req_via_TCP(...)
handle_AUTH_HELLO(...)
send_auth_request_message(...)
save_distribution_key(...)
parse_session_key_response(...)
```

The C TCP workflow is:

1. Open a TCP connection to Auth.
2. Wait for `AUTH_HELLO`.
3. Parse Auth ID and Auth nonce.
4. Generate the entity nonce.
5. Serialize the cleartext session-key request.
6. If no valid distribution key exists, encrypt/sign with public-key crypto and
   send `SESSION_KEY_REQ_IN_PUB_ENC`.
7. If a valid distribution key exists, encrypt/MAC with the distribution key and
   send `SESSION_KEY_REQ`.
8. Read either `SESSION_KEY_RESP_WITH_DIST_KEY`, `SESSION_KEY_RESP`, or
   `AUTH_ALERT`.
9. Decrypt and verify the response.
10. Check that the response nonce matches the entity nonce.
11. Save the new distribution key, if Auth included one.
12. Save returned session keys in the session-key cache.

Important compatibility note:

- The C and Node TCP paths connect and wait for Auth's `AUTH_HELLO`.
- They do not send `ENTITY_HELLO` first on TCP.
- `ENTITY_HELLO` appears in the UDP flow, but UDP is not part of Step 6.

### Proposed Python modules

Step 6 should add:

```text
entity/python/iotauth/
  auth_service.py
  transports/
    __init__.py
    tcp.py
```

Suggested responsibilities:

- `auth_service.py`
  - Own the Auth session-key request workflow.
  - Convert config/context values into `SessionKeyRequestPayload`.
  - Choose public-key mode or distribution-key mode.
  - Decrypt and parse Auth responses.
  - Update `ctx.distribution_key` and `ctx.session_keys`.
- `transports/tcp.py`
  - Open TCP sockets.
  - Send one encoded IoTSP frame.
  - Read exactly one IoTSP frame, even when TCP splits it across reads.
  - Convert low-level socket errors into `AuthConnectionError`.

The transport layer should know about bytes and frames, but it should not know
how session keys work. The Auth service should know the protocol workflow, but
it should not contain raw socket read loops.

### Proposed public API

Initial function:

```python
def request_session_keys(
    ctx: IoTAuthContext,
    *,
    purpose: dict[str, object] | str | None = None,
    count: int | None = None,
    timeout: float | None = 5.0,
) -> list[SessionKey]:
    ...
```

Behavior:

- `purpose=None` means use the first purpose from `ctx.config.purposes`.
- `count=None` means use `ctx.config.num_keys`.
- `timeout` applies to connecting and reading from Auth.
- Returned keys are also added to `ctx.session_keys`.
- If Auth returns a new distribution key, store it in `ctx.distribution_key`.

Later convenience method:

```python
class IoTAuthContext:
    def request_session_keys(...):
        return request_session_keys(self, ...)
```

### Request construction

When `AUTH_HELLO` arrives, Python should parse:

```python
hello = parse_auth_hello_payload(frame.payload)
```

Then validate:

- `frame.message_type == MessageType.AUTH_HELLO`
- `hello.auth_id == ctx.config.auth.id`
- `len(hello.nonce) == NONCE_SIZE`

Then generate a fresh entity nonce:

```python
entity_nonce = secrets.token_bytes(NONCE_SIZE)
```

Then build:

```python
request = SessionKeyRequestPayload(
    entity_nonce=entity_nonce,
    auth_nonce=hello.nonce,
    num_keys=count,
    entity_name=ctx.config.entity.name,
    purpose=purpose,
)
```

Then serialize it with Step 4:

```python
payload = serialize_session_key_request_payload(request)
```

### Choosing the request protection mode

The first Step 6 implementation can use this rule:

```python
if ctx.distribution_key is None or distribution_key_is_expired(ctx.distribution_key):
    protected = encrypt_and_sign_for_auth(payload, ctx)
    message_type = MessageType.SESSION_KEY_REQ_IN_PUB_ENC
else:
    protected = encrypt_request_with_distribution_key(
        payload,
        ctx.config.entity.name,
        ctx.distribution_key,
    )
    message_type = MessageType.SESSION_KEY_REQ
```

Open implementation choice:

- Distribution-key expiration is currently stored as an integer parsed from the
  wire format. Before Step 6 implementation, we should confirm whether the Java
  and C code treat this as epoch seconds, milliseconds, or IoTAuth-specific
  packed time.
- If there is any uncertainty, Step 6 can initially treat `None` as invalid and
  non-`None` as valid only in tests with explicit fixtures. Then we can tighten
  expiration validation after checking the Java Auth behavior.

### TCP frame transport

Step 3 already has frame serialization logic. Step 6 needs socket helpers that
can move those frames over TCP safely.

Proposed helpers:

```python
def send_frame(sock: socket.socket, frame: IoTSPFrame) -> None:
    ...

def recv_frame(sock: socket.socket, *, max_payload_size: int = 65536) -> IoTSPFrame:
    ...
```

`recv_frame` is important because TCP is a stream, not a message queue. One
`socket.recv(...)` call may return:

- less than one full frame,
- exactly one frame,
- one frame plus bytes from the next frame.

The C code handles this by reading the message type, reading the variable-length
payload length one byte at a time, then reading exactly that many payload bytes.
Python should follow the same idea.

For Step 6, it is enough to read one complete frame at a time. We do not need a
full reusable buffered stream parser until the secure channel step.

### Response handling

Auth can return three important message types in this step.

#### `SESSION_KEY_RESP_WITH_DIST_KEY`

This response is used when Python requested a new distribution key.

Expected payload shape:

```text
encrypted_distribution_key: RSA key size bytes
distribution_key_signature: RSA key size bytes
encrypted_session_key_response: remaining bytes
```

Handling:

1. Split the first `2 * rsa_key_size` bytes.
2. Verify and decrypt the distribution key with
   `verify_and_decrypt_from_auth(...)`.
3. Parse the decrypted distribution-key record with
   `parse_distribution_key_record(...)`.
4. Store the result on `ctx.distribution_key`.
5. Decrypt the remaining response bytes with the distribution key.
6. Parse the plaintext with `parse_session_key_response_payload(...)`.
7. Verify the response entity nonce equals the nonce Python generated.
8. Store every returned session key in `ctx.session_keys`.

#### `SESSION_KEY_RESP`

This response is used when Python already has a valid distribution key.

Handling:

1. Require `ctx.distribution_key`.
2. Decrypt the response payload with that distribution key.
3. Parse the plaintext with `parse_session_key_response_payload(...)`.
4. Verify the response entity nonce.
5. Store returned session keys in `ctx.session_keys`.

#### `AUTH_ALERT`

Handling:

1. Parse with `parse_auth_alert_payload(...)`.
2. Raise `AuthProtocolError` with the alert code and a readable message.

Known alert codes from C:

- `INVALID_DISTRIBUTION_KEY`
- `INVALID_SESSION_KEY_REQ`
- `UNKNOWN_INTERNAL_ERROR`

If Python does not yet have named constants for those alert codes, Step 6 can
start by reporting the numeric code.

### Error model additions

Step 6 should add:

- `AuthConnectionError`: TCP connect, read, write, timeout, or early close.
- `AuthProtocolError`: validly framed Auth message is unexpected or rejected.

`AuthProtocolError` already exists in `exceptions.py`; Step 6 should add
`AuthConnectionError`.

Suggested behavior:

- Use `AuthConnectionError` for socket-level failures.
- Use `SerializationError` for malformed frames or malformed payload bytes.
- Use `AuthProtocolError` for wrong Auth ID, wrong message type, bad nonce, or
  `AUTH_ALERT`.
- Use `MessageIntegrityError` for failed signatures, HMACs, AEAD tags, or
  decrypt-auth failures.

### Tests to add

Unit tests should cover the workflow without requiring a real Auth server:

- `recv_frame` reads a frame whose header and payload arrive in multiple chunks.
- `recv_frame` rejects payloads larger than `max_payload_size`.
- `request_session_keys` rejects a first frame that is not `AUTH_HELLO`.
- `request_session_keys` rejects an `AUTH_HELLO` with the wrong Auth ID.
- Public-key request mode sends `SESSION_KEY_REQ_IN_PUB_ENC` when
  `ctx.distribution_key is None`.
- Distribution-key request mode sends `SESSION_KEY_REQ` when a valid
  distribution key exists.
- `SESSION_KEY_RESP_WITH_DIST_KEY` updates `ctx.distribution_key`.
- Returned session keys are added to `ctx.session_keys`.
- Response nonce mismatch raises `AuthProtocolError`.
- `AUTH_ALERT` raises `AuthProtocolError`.
- Socket timeout or early close raises `AuthConnectionError`.

Integration tests can come after the unit behavior is stable:

- Start or connect to the Java Auth server.
- Load an existing C-style config.
- Request one or more session keys.
- Confirm the returned key IDs and key material are stored in the Python cache.

### Step 6 repo references

Python references from previous steps:

- `entity/python/iotauth/context.py`
  - `IoTAuthContext`: runtime state to pass into the Auth service.
- `entity/python/iotauth/messages.py`
  - `MessageType`
  - `IoTSPFrame`
- `entity/python/iotauth/auth_messages.py`
  - `parse_auth_hello_payload(...)`
  - `parse_auth_alert_payload(...)`
  - `SessionKeyRequestPayload`
  - `serialize_session_key_request_payload(...)`
  - `parse_distribution_key_record(...)`
  - `parse_session_key_response_payload(...)`
- `entity/python/iotauth/crypto.py`
  - `encrypt_and_sign_for_auth(...)`
  - `verify_and_decrypt_from_auth(...)`
  - `encrypt_request_with_distribution_key(...)`
  - `symmetric_decrypt_authenticate(...)`
- `entity/python/iotauth/keys.py`
  - `DistributionKey`
  - `SessionKey`
  - `SessionKeyCache.add(...)`
- `entity/python/iotauth/exceptions.py`
  - `AuthProtocolError`
  - `MessageIntegrityError`
  - `SerializationError`

C references:

- `entity/c/src/c_secure_comm.c`
  - `send_session_key_req_via_TCP(...)`: main TCP session-key request flow.
  - `handle_AUTH_HELLO(...)`: Auth hello parsing and request creation.
  - `send_auth_request_message(...)`: chooses public-key or distribution-key
    protection.
  - `save_distribution_key(...)`: verifies and decrypts a new distribution key.
  - `parse_session_key_response(...)`: parses decrypted session-key responses.
- `entity/c/src/c_common.c`
  - `parse_received_message(...)`: message type plus variable-length payload
    parsing.
  - `read_header_return_data_buf_pointer(...)`: reads one TCP frame from a
    stream.
  - `make_sender_buf(...)`: builds an IoTSP frame for sending.
- `entity/c/src/c_common.h`
  - TCP helper declarations and message framing comments.

Node references:

- `entity/node/accessors/node_modules/iotAuthService.js`
  - `sendSessionKeyReqViaTCP(...)`: Node TCP workflow and fragmented payload
    handling.
  - `sendSessionKeyReqHelper(...)`: Auth hello, request selection, response
    parsing, and nonce verification.
- `entity/node/accessors/node_modules/common.js`
  - `serializeIoTSP(...)`
  - `parseIoTSP(...)`

### Learning notes

Topics worth studying for this step:

- Python `socket` module:
  <https://docs.python.org/3/library/socket.html>
- Why TCP is a byte stream, not message-based:
  <https://docs.python.org/3/howto/sockets.html>
- `socket.create_connection(...)` for client connections:
  <https://docs.python.org/3/library/socket.html#socket.create_connection>
- `secrets.token_bytes(...)` for cryptographic nonces:
  <https://docs.python.org/3/library/secrets.html#secrets.token_bytes>
- Context managers with sockets, similar in spirit to making sure C code always
  closes file descriptors:
  <https://docs.python.org/3/reference/datamodel.html#context-managers>

### Expected verification command after implementation

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Documentation status:

- Step 6 is documented here.

### Step 6 implementation references

The Step 6 Auth TCP session-key request workflow has now been implemented.

Python files:

- `entity/python/iotauth/auth_service.py`
  - `request_session_keys(...)`: public Auth workflow that connects to Auth,
    receives `AUTH_HELLO`, builds the session-key request, sends the protected
    request frame, parses the response, and stores returned keys in
    `ctx.session_keys`.
  - `distribution_key_is_expired(...)`: checks distribution-key absolute
    validity using epoch milliseconds, matching the C and Node behavior.
  - `_protect_session_key_request(...)`: chooses
    `SESSION_KEY_REQ_IN_PUB_ENC` when no valid distribution key exists, or
    `SESSION_KEY_REQ` when a distribution key can be reused.
  - `_handle_session_key_response(...)`: handles `SESSION_KEY_RESP`,
    `SESSION_KEY_RESP_WITH_DIST_KEY`, and `AUTH_ALERT`.
  - `_decrypt_response_with_new_distribution_key(...)`: verifies/decrypts a new
    distribution key, stores it on the context, then decrypts the session-key
    response.
  - `_decrypt_response_with_existing_distribution_key(...)`: decrypts a response
    using the cached distribution key.
- `entity/python/iotauth/transports/tcp.py`
  - `connect(...)`: opens a TCP connection to Auth.
  - `send_frame(...)`: serializes and writes one IoTSP frame.
  - `recv_frame(...)`: reads one complete IoTSP frame from a TCP stream, even
    when the frame arrives across multiple reads.
- `entity/python/iotauth/transports/__init__.py`
  - Exports the TCP transport helpers.
- `entity/python/iotauth/context.py`
  - `IoTAuthContext.request_session_keys(...)`: convenience method that
    delegates to `auth_service.request_session_keys(...)`.
- `entity/python/iotauth/exceptions.py`
  - Added `AuthConnectionError` for TCP connect, read, write, timeout, and
    early-close failures.
- `entity/python/iotauth/__init__.py`
  - Exports `request_session_keys`, `distribution_key_is_expired`,
    `AuthConnectionError`, `send_frame`, and `recv_frame`.
- `entity/python/tests/test_auth_service.py`
  - Tests Auth hello validation, request protection-mode selection,
    `AUTH_ALERT` handling, response nonce validation, new distribution-key
    storage, session-key cache updates, and the context convenience method.
- `entity/python/tests/test_tcp_transport.py`
  - Tests fragmented TCP frame reads, oversized payload rejection, early socket
    close handling, and frame writes.

Implementation notes:

- Step 6 uses TCP only. UDP remains a later milestone.
- The TCP path follows the C and Node behavior: connect to Auth and wait for
  `AUTH_HELLO`; do not send `ENTITY_HELLO` first on TCP.
- Absolute key validity is interpreted as epoch milliseconds. This matches
  `check_validity(...)` in C and `new Date(...)` parsing in Node.
- Unit tests use fake sockets and patched crypto boundaries for protocol-flow
  cases. Real crypto behavior remains covered by the Step 5 tests.
- Step 6 still does not implement the entity-to-entity secure channel,
  handshake, or `SecureChannel.send()` / `SecureChannel.recv()`.

Verification command:

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 74 tests
OK
```

## Step 7: TCP secure client handshake design

After Step 6, Python can request session keys from Auth and store them in
`ctx.session_keys`. Step 7 should use one cached session key to start secure
entity-to-entity communication over TCP.

This step should implement the handshake bytes and the client-side connection
flow. It should not yet implement the server accept loop, encrypted application
messages, sequence numbers, or the final ergonomic `SecureClient` and
`SecureServer` APIs.

### Goal

At the end of Step 7, Python should be able to open a TCP connection to a
target entity and complete the three-message session-key handshake:

```python
ctx = IoTAuthContext.from_config("entity/python/examples/configs/client.config")
keys = ctx.request_session_keys()

channel = connect_secure(ctx, key=keys[0])
```

The returned object can be a small `SecureChannel` placeholder at first. For
Step 7, it only needs to prove that the handshake completed and preserve the
socket, session key, and initial sequence-number state for the next step.

### Why this comes next

Step 6 gets key material. Step 7 proves both entities actually possess the same
session key without exposing the key on the wire.

The handshake is a nonce challenge-response:

1. Client sends a fresh client nonce encrypted with the session key.
2. Server decrypts it, proves it saw the client nonce, and sends a fresh server
   nonce.
3. Client verifies the reply to its nonce, then proves it saw the server nonce.

From a C point of view, this is similar to moving from "I have a pointer to a
`session_key_t`" to "I have a live `SST_session_ctx_t` that is ready for secure
messages."

### Scope for Step 7

Step 7 should include:

- Handshake payload dataclass.
- Handshake payload serializer.
- Handshake payload parser.
- Client-side `SKEY_HANDSHAKE_1` builder.
- Client-side `SKEY_HANDSHAKE_2` verifier.
- Client-side `SKEY_HANDSHAKE_3` builder.
- `connect_secure(...)` helper that opens a target TCP socket and performs the
  client handshake.
- Minimal `SecureChannel` state object with socket, session key, and sequence
  numbers initialized to zero.

Step 7 should not include:

- Server-side accept/handshake flow.
- `SECURE_COMM_MSG` send/receive.
- Sequence-number encryption and validation.
- Session-key request by key ID for a server cache miss.
- Diffie-Hellman session-key derivation.
- Asyncio support.

### C mental model

The C client flow is in `entity/c/src/c_api.c`:

```c
secure_connect_to_server_with_socket(...)
```

That function:

1. Initializes `SST_session_ctx_t`.
2. Calls `parse_handshake_1(...)`.
3. Sends `SKEY_HANDSHAKE_1`.
4. Reads `SKEY_HANDSHAKE_2`.
5. Calls `check_handshake_2_send_handshake_3(...)`.
6. Sends `SKEY_HANDSHAKE_3`.
7. Updates session-key validity.
8. Switches to `IN_COMM`.

The lower-level C helpers live in `entity/c/src/c_secure_comm.c`:

```c
parse_handshake_1(...)
check_handshake_2_send_handshake_3(...)
```

The shared handshake payload format lives in `entity/c/src/c_common.c`:

```c
serialize_handshake(...)
parse_handshake(...)
```

### Handshake payload format

The cleartext handshake payload has this shape before encryption:

```text
indicator: 1 byte
client/server nonce slot: 8 bytes
reply nonce slot: 8 bytes
optional Diffie-Hellman bytes: remaining bytes
```

The indicator byte is a bit field:

- bit `0x01`: `nonce` is present.
- bit `0x02`: `reply_nonce` is present.
- bit `0x04`: Diffie-Hellman parameter is present.

For the first TCP secure-client milestone, Python should support only nonces:

- Handshake 1 cleartext: indicator `0x01`, `nonce=client_nonce`.
- Handshake 2 cleartext: indicator `0x03`, `nonce=server_nonce`,
  `reply_nonce=client_nonce`.
- Handshake 3 cleartext: indicator `0x02`, `reply_nonce=server_nonce`.

C sometimes serializes handshake 3 as both `nonce` and `reply_nonce`, but the
Node client sends only `replyNonce` in handshake 3. Python should match the
Node/C parser-compatible shape first: handshake 3 needs to prove the server
nonce, so `reply_nonce` is the required field.

### Proposed Python modules

Step 7 should add:

```text
entity/python/iotauth/
  handshake.py
  secure_channel.py
```

Suggested responsibilities:

- `handshake.py`
  - Define `HandshakePayload`.
  - Serialize and parse cleartext handshake payloads.
  - Build encrypted handshake 1 payload.
  - Verify encrypted handshake 2 and build encrypted handshake 3.
- `secure_channel.py`
  - Define minimal `SecureChannel`.
  - Define `connect_secure(...)`.
  - Resolve target server host/port from config.
  - Open TCP connection.
  - Send and receive handshake frames.
  - Return a channel object after successful handshake.

Step 7 can reuse `entity/python/iotauth/transports/tcp.py` from Step 6 for
socket connection, frame send, and frame receive.

### Proposed public API

Initial API:

```python
from iotauth import connect_secure

channel = connect_secure(ctx, key=session_key)
```

Optional target override:

```python
channel = connect_secure(ctx, key=session_key, host="127.0.0.1", port=21100)
```

If `host` and `port` are not provided, `connect_secure(...)` should use the
first target in `ctx.config.targets`.

Future convenience API:

```python
channel = ctx.connect_secure(key=session_key)
```

That convenience method can be added after the standalone helper is stable.

### Minimal SecureChannel object

Step 7 should create the smallest useful channel state:

```python
@dataclass
class SecureChannel:
    socket: socket.socket
    session_key: SessionKey
    send_sequence: int = 0
    receive_sequence: int = 0
    closed: bool = False
```

It should not yet expose `send(...)` or `recv(...)` unless those methods raise a
clear "not implemented yet" exception. The next step should turn this state
object into the real encrypted application-data channel.

### Client handshake flow

The client side should do:

1. Choose a session key.
2. Generate `client_nonce = secrets.token_bytes(8)`.
3. Serialize cleartext handshake 1 with only `client_nonce`.
4. Encrypt/authenticate it with the session key.
5. Prefix the session key ID.
6. Send `SKEY_HANDSHAKE_1`.
7. Receive `SKEY_HANDSHAKE_2`.
8. Decrypt/authenticate handshake 2 with the same session key.
9. Parse handshake 2.
10. Verify `reply_nonce == client_nonce`.
11. Extract `server_nonce`.
12. Serialize cleartext handshake 3 with `reply_nonce=server_nonce`.
13. Encrypt/authenticate it with the same session key.
14. Send `SKEY_HANDSHAKE_3`.
15. Return `SecureChannel`.

### Encryption mode

The C handshake helpers use `symmetric_encrypt_authenticate(...)` with the
session key and no extra HMAC flag in the call site. Python should use the
`SessionKey` fields:

```python
symmetric_encrypt_authenticate(
    plaintext,
    key.cipher_key,
    key.mac_key,
    key.encryption_mode,
    key.hmac_enabled,
)
```

This keeps the Python behavior aligned with the parsed session-key config.

### Error model additions

Step 7 should add:

- `SecureHandshakeError`: wrong handshake message type, nonce mismatch, missing
  nonce field, or invalid handshake state.
- `ExpiredKeyError`: selected session key is expired.

The README already lists these in the planned error model, but the classes do
not exist yet. Step 7 should add them to `exceptions.py` and export them.

Suggested behavior:

- Use `AuthConnectionError` for TCP socket failures because the same TCP helper
  is used.
- Use `SerializationError` for malformed handshake bytes.
- Use `MessageIntegrityError` for decrypt/MAC failures.
- Use `SecureHandshakeError` for valid decrypted handshake bytes that do not
  satisfy the expected protocol state.
- Use `ExpiredKeyError` if the chosen session key has expired before or during
  handshake.

### Session-key validity

C calls `update_validity(s_key)` after a successful handshake. Python should
first do the simpler safety check:

- If `SessionKey.abs_validity` is present and current epoch milliseconds are
  greater than or equal to it, reject the key.

Later we can decide whether Python should update `abs_validity` using
`rel_validity` after handshake, exactly as C does.

### Tests to add

Handshake payload tests:

- Serialize nonce-only payload with indicator `0x01`.
- Serialize reply-nonce-only payload with indicator `0x02`.
- Serialize nonce plus reply nonce with indicator `0x03`.
- Reject payload with neither nonce nor reply nonce.
- Parse nonce-only payload.
- Parse nonce plus reply nonce.
- Reject truncated nonce fields.

Client handshake tests with fake sockets:

- `connect_secure(...)` sends `SKEY_HANDSHAKE_1` with the selected session key
  ID prefix.
- `connect_secure(...)` accepts valid `SKEY_HANDSHAKE_2` and sends
  `SKEY_HANDSHAKE_3`.
- Response nonce mismatch raises `SecureHandshakeError`.
- Wrong response message type raises `SecureHandshakeError`.
- Expired session key raises `ExpiredKeyError`.
- TCP early close still raises `AuthConnectionError`.

Crypto-backed round-trip tests:

- Build handshake 1, decrypt it with the same session key, and verify the
  parsed nonce.
- Build handshake 2, verify it, and build handshake 3.
- Tampering with encrypted handshake 2 raises `MessageIntegrityError`.

### Step 7 repo references

Python references from previous steps:

- `entity/python/iotauth/auth_service.py`
  - `request_session_keys(...)`: obtains the session keys Step 7 consumes.
- `entity/python/iotauth/keys.py`
  - `SessionKey`: key material and key ID used by the handshake.
  - `SessionKeyCache`: source of cached session keys.
- `entity/python/iotauth/messages.py`
  - `MessageType.SKEY_HANDSHAKE_1`
  - `MessageType.SKEY_HANDSHAKE_2`
  - `MessageType.SKEY_HANDSHAKE_3`
  - `IoTSPFrame`
- `entity/python/iotauth/transports/tcp.py`
  - `connect(...)`
  - `send_frame(...)`
  - `recv_frame(...)`
- `entity/python/iotauth/crypto.py`
  - `symmetric_encrypt_authenticate(...)`
  - `symmetric_decrypt_authenticate(...)`
- `entity/python/iotauth/config.py`
  - `TargetServer`
  - `EntityConfig.targets`

C references:

- `entity/c/src/c_api.c`
  - `secure_connect_to_server_with_socket(...)`: client-side secure handshake.
  - `server_secure_comm_setup(...)`: server-side behavior that Step 7 must
    interoperate with later.
- `entity/c/src/c_secure_comm.c`
  - `parse_handshake_1(...)`: builds encrypted handshake 1.
  - `check_handshake_2_send_handshake_3(...)`: verifies handshake 2 and builds
    handshake 3.
  - `check_handshake1_send_handshake2(...)`: server-side counterpart for later.
- `entity/c/src/c_common.c`
  - `serialize_handshake(...)`
  - `parse_handshake(...)`
- `entity/c/src/c_common.h`
  - `HS_NONCE_SIZE`
  - `HS_INDICATOR_SIZE`
  - `SKEY_HANDSHAKE_1`, `SKEY_HANDSHAKE_2`, `SKEY_HANDSHAKE_3`

Node references:

- `entity/node/accessors/node_modules/iotSecureClient.js`
  - Client-side handshake 1, handshake 2 verification, and handshake 3 send.
- `entity/node/accessors/node_modules/iotSecureServer.js`
  - Server-side handshake behavior Python must interoperate with later.
- `entity/node/accessors/node_modules/common.js`
  - `generateHSNonce(...)`
  - `serializeHandshake(...)`
  - `parseHandshake(...)`

### Learning notes

Topics worth studying for this step:

- Challenge-response authentication:
  <https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication>
- Why nonces prevent replay attacks:
  <https://en.wikipedia.org/wiki/Cryptographic_nonce>
- Python `dataclasses` for small protocol objects:
  <https://docs.python.org/3/library/dataclasses.html>
- `secrets.token_bytes(...)` for secure random handshake nonces:
  <https://docs.python.org/3/library/secrets.html#secrets.token_bytes>
- Designing small state objects before adding behavior-heavy methods.

### Expected verification command after implementation

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Documentation status:

- Step 7 is documented here.

### Step 7 implementation references

The Step 7 TCP secure client handshake layer has now been implemented.

Python files:

- `entity/python/iotauth/handshake.py`
  - `HandshakePayload`: cleartext handshake payload dataclass.
  - `serialize_handshake_payload(...)`: serializes nonce, reply nonce, and
    optional Diffie-Hellman bytes using the IoTAuth indicator-byte format.
  - `parse_handshake_payload(...)`: parses decrypted handshake payload bytes.
  - `build_handshake_1(...)`: builds encrypted `SKEY_HANDSHAKE_1` payload bytes
    with the session key ID prefix.
  - `verify_handshake_2_and_build_handshake_3(...)`: decrypts handshake 2,
    verifies the client nonce, extracts the server nonce, and builds encrypted
    handshake 3.
  - `HANDSHAKE_NONCE_PRESENT`, `HANDSHAKE_REPLY_NONCE_PRESENT`,
    `HANDSHAKE_DH_PARAM_PRESENT`, and `HANDSHAKE_FIXED_SIZE`: protocol
    constants for the handshake indicator and fixed nonce slots.
- `entity/python/iotauth/secure_channel.py`
  - `SecureChannel`: minimal channel state containing socket, session key, send
    sequence, receive sequence, and closed state.
  - `connect_secure(...)`: opens a target TCP socket, sends
    `SKEY_HANDSHAKE_1`, verifies `SKEY_HANDSHAKE_2`, sends
    `SKEY_HANDSHAKE_3`, and returns `SecureChannel`.
  - `session_key_is_expired(...)`: checks session-key absolute validity using
    epoch milliseconds.
- `entity/python/iotauth/context.py`
  - `IoTAuthContext.connect_secure(...)`: convenience method that delegates to
    `secure_channel.connect_secure(...)`.
- `entity/python/iotauth/exceptions.py`
  - Added `SecureHandshakeError`.
  - Added `ExpiredKeyError`.
- `entity/python/iotauth/__init__.py`
  - Exports Step 7 handshake helpers, `SecureChannel`, `connect_secure`,
    `session_key_is_expired`, `SecureHandshakeError`, and `ExpiredKeyError`.
- `entity/python/tests/test_handshake.py`
  - Tests handshake indicator serialization, parsing, invalid payloads,
    handshake 1 key-ID prefixing, handshake 2 nonce verification, handshake 3
    construction, and crypto-backed tamper detection.
- `entity/python/tests/test_secure_channel.py`
  - Tests client handshake frame order, target resolution, host/port override,
    wrong response type handling, nonce mismatch handling, expired key handling,
    TCP early-close handling, and the context convenience method.

Implementation notes:

- Step 7 implements only the client-side TCP secure handshake.
- Server-side accept/handshake handling is still a later step.
- `SecureChannel` is intentionally minimal. It stores the socket and sequence
  counters, but does not yet implement encrypted `send(...)` or `recv(...)`.
- Handshake 3 is serialized with `reply_nonce=server_nonce`, matching the Node
  client shape and the C/Node parser-compatible protocol.
- Session-key expiration is interpreted as epoch milliseconds, matching the
  absolute-validity behavior used elsewhere in the repo.

Verification command:

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 94 tests
OK
```

## Step 8: TCP secure server handshake design

After Step 7, Python can act as a secure TCP client: it can use a cached session
key, connect to another entity, and complete `SKEY_HANDSHAKE_1`,
`SKEY_HANDSHAKE_2`, and `SKEY_HANDSHAKE_3` from the client side.

Step 8 should implement the server-side counterpart. The Python API should be
able to accept one already-connected TCP socket, complete the secure handshake
using a cached session key, and return a `SecureChannel`.

This step should still not implement encrypted application messages,
`SecureChannel.send()`, `SecureChannel.recv()`, or a full `SecureServer`
listener loop. Those should follow once both sides can create a channel.

### Goal

At the end of Step 8, application or test code should be able to do this:

```python
ctx = IoTAuthContext.from_config("entity/python/examples/configs/server.config")

client_socket, address = listening_socket.accept()
channel = accept_secure(ctx, client_socket)
```

The returned `SecureChannel` should contain:

- the accepted socket,
- the session key selected by handshake 1's key ID,
- send and receive sequence counters initialized to zero,
- `closed=False`.

### Why this comes next

Step 7 lets Python initiate a secure connection. Step 8 lets Python answer one.
Together, they complete the minimum entity-to-entity handshake foundation:

- Python client to Python server in tests.
- Python client to C/Node server later.
- C/Node client to Python server later.

This is the server-side version of the same challenge-response proof:

1. Server receives handshake 1.
2. Server reads the session key ID.
3. Server finds the matching session key.
4. Server decrypts the client's nonce.
5. Server sends its own nonce and echoes the client nonce.
6. Server receives handshake 3.
7. Server verifies that the client echoed the server nonce.

### Scope for Step 8

Step 8 should include:

- Server-side handshake 1 parser/verifier.
- Server-side handshake 2 builder.
- Server-side handshake 3 verifier.
- `accept_secure(...)` helper that performs the server-side handshake on an
  already-connected socket.
- Session-key lookup from `ctx.session_keys` using the key ID included in
  handshake 1.
- Minimal tests proving Step 7's client helper and Step 8's server helper can
  interoperate through fake sockets or an in-memory socket pair.

Step 8 should not include:

- A long-running `SecureServer.serve_forever()` loop.
- Threading or async connection management.
- Server-side key-ID request to Auth when a key is missing.
- Encrypted application data frames.
- Sequence-number validation.
- Diffie-Hellman session-key derivation.

### C mental model

The C server-side flow is in `entity/c/src/c_api.c`:

```c
server_secure_comm_setup(...)
```

That function:

1. Reads `SKEY_HANDSHAKE_1`.
2. Extracts the session key ID from the first 8 payload bytes.
3. Looks up the matching session key.
4. Calls `check_handshake1_send_handshake2(...)`.
5. Sends `SKEY_HANDSHAKE_2`.
6. Reads `SKEY_HANDSHAKE_3`.
7. Decrypts and parses handshake 3.
8. Verifies `reply_nonce == server_nonce`.
9. Copies the selected session key into the session context.
10. Switches to `IN_COMM`.

The lower-level C helper is in `entity/c/src/c_secure_comm.c`:

```c
check_handshake1_send_handshake2(...)
```

That helper decrypts handshake 1, parses the client's nonce, generates the
server nonce, serializes handshake 2, and encrypts it with the selected session
key.

### Node mental model

The Node server flow is split between:

- `entity/node/accessors/node_modules/iotSecureServer.js`
- `entity/node/accessors/SecureCommServer.js`

The important behavior is:

1. `SKEY_HANDSHAKE_1` arrives.
2. `SecureCommServer.js` reads the key ID from the first 8 bytes.
3. If the key is cached, it calls `sendHandshake2(...)`.
4. `sendHandshake2(...)` decrypts the rest of handshake 1.
5. It sends `SKEY_HANDSHAKE_2` with server nonce and client reply nonce.
6. Later it receives `SKEY_HANDSHAKE_3`.
7. It verifies the client's reply nonce equals the server nonce.

Python Step 8 should match this behavior for the cached-key path. The cache-miss
path, where the server asks Auth for the key by ID, should remain a later step.

### Proposed Python module changes

Step 8 should build on the files introduced in Step 7:

```text
entity/python/iotauth/
  handshake.py
  secure_channel.py
```

Suggested additions to `handshake.py`:

- `parse_handshake_1_key_id(payload) -> bytes`
- `verify_handshake_1_and_build_handshake_2(key, payload, server_nonce)`
- `verify_handshake_3(key, encrypted_handshake_3, server_nonce)`

Suggested additions to `secure_channel.py`:

- `accept_secure(ctx, sock, timeout=5.0) -> SecureChannel`
- Optional helper `_lookup_session_key(ctx, key_id)`

Step 8 should reuse:

- `recv_frame(...)`
- `send_frame(...)`
- `parse_handshake_payload(...)`
- `serialize_handshake_payload(...)`
- `symmetric_encrypt_authenticate(...)`
- `symmetric_decrypt_authenticate(...)`
- `SecureChannel`
- `session_key_is_expired(...)`

### Proposed public API

Initial API:

```python
from iotauth import accept_secure

channel = accept_secure(ctx, client_socket)
```

Future higher-level server API:

```python
server = SecureServer(ctx)
server.serve_forever()
```

The higher-level server should wait until after Step 8, because first we need a
well-tested single-connection handshake primitive.

### Server handshake flow

`accept_secure(...)` should do:

1. Read one IoTSP frame from the socket.
2. Require `frame.message_type == MessageType.SKEY_HANDSHAKE_1`.
3. Require the payload to be at least `SESSION_KEY_ID_SIZE + encrypted bytes`.
4. Extract `key_id = payload[:8]`.
5. Look up `key = ctx.session_keys.require(key_id)`.
6. Reject the key if expired.
7. Decrypt `payload[8:]` with the selected session key.
8. Parse handshake 1 and require `nonce` to be present.
9. Generate `server_nonce = secrets.token_bytes(8)`.
10. Serialize handshake 2 with `nonce=server_nonce` and
    `reply_nonce=client_nonce`.
11. Encrypt handshake 2 with the selected session key.
12. Send `SKEY_HANDSHAKE_2`.
13. Read the next IoTSP frame.
14. Require `frame.message_type == MessageType.SKEY_HANDSHAKE_3`.
15. Decrypt and parse handshake 3.
16. Require `reply_nonce == server_nonce`.
17. Reject if the key expired during the handshake.
18. Return `SecureChannel(socket=sock, session_key=key)`.

### Error behavior

Step 8 should use the same exceptions introduced earlier:

- `AuthConnectionError`: socket read/write/early-close failure.
- `SerializationError`: malformed frame or malformed handshake bytes.
- `MessageIntegrityError`: encrypted handshake payload fails decrypt/MAC.
- `SecureHandshakeError`: wrong message type, missing key ID, unknown key ID,
  missing nonce, nonce mismatch, or invalid handshake state.
- `ExpiredKeyError`: selected session key is expired.

Open choice:

- `SessionKeyCache.require(...)` currently raises `KeyCacheError` when the key
  is missing. For Step 8, `accept_secure(...)` can catch that and raise
  `SecureHandshakeError`, because from the handshake caller's point of view this
  is a protocol failure.

### Key-ID cache miss

C and Node both have plans for server-side cache misses:

- If the server does not have the requested session key, ask Auth for a session
  key by ID.
- Then continue the handshake.

Step 8 should not implement that. The first server handshake should require the
key to already exist in `ctx.session_keys`. This keeps the implementation small
and testable. A later step can add "request by key ID" once the basic server
handshake works.

### Tests to add

Handshake helper tests:

- Extract key ID from handshake 1 payload.
- Reject handshake 1 payload shorter than 8 bytes.
- Verify handshake 1 decrypts and returns the client nonce.
- Build handshake 2 with server nonce and client reply nonce.
- Verify handshake 3 accepts matching `reply_nonce`.
- Verify handshake 3 rejects nonce mismatch.

Server accept tests with fake sockets:

- `accept_secure(...)` reads `SKEY_HANDSHAKE_1`, sends `SKEY_HANDSHAKE_2`, reads
  `SKEY_HANDSHAKE_3`, and returns `SecureChannel`.
- Unknown session key ID raises `SecureHandshakeError`.
- Wrong first frame type raises `SecureHandshakeError`.
- Wrong third frame type raises `SecureHandshakeError`.
- Expired session key raises `ExpiredKeyError`.
- TCP early close raises `AuthConnectionError`.
- Failed handshake closes the socket or leaves closure behavior clearly
  documented.

Interoperability-style unit test:

- Use Step 7 client helper and Step 8 server helper with a socket pair or a fake
  duplex socket to prove the generated handshake messages are compatible.

Crypto-backed tests:

- Build handshake 1 with a real session key and verify the server-side helper
  decrypts it.
- Build handshake 2 and verify Step 7's client-side helper accepts it.
- Build handshake 3 and verify Step 8's server-side helper accepts it.
- Tamper with handshake 3 and expect `MessageIntegrityError`.

### Step 8 repo references

Python references from previous steps:

- `entity/python/iotauth/handshake.py`
  - `HandshakePayload`
  - `serialize_handshake_payload(...)`
  - `parse_handshake_payload(...)`
  - `build_handshake_1(...)`
  - `verify_handshake_2_and_build_handshake_3(...)`
- `entity/python/iotauth/secure_channel.py`
  - `SecureChannel`
  - `connect_secure(...)`
  - `session_key_is_expired(...)`
- `entity/python/iotauth/keys.py`
  - `SessionKey`
  - `SessionKeyCache.require(...)`
- `entity/python/iotauth/messages.py`
  - `MessageType.SKEY_HANDSHAKE_1`
  - `MessageType.SKEY_HANDSHAKE_2`
  - `MessageType.SKEY_HANDSHAKE_3`
  - `IoTSPFrame`
- `entity/python/iotauth/transports/tcp.py`
  - `recv_frame(...)`
  - `send_frame(...)`
- `entity/python/iotauth/exceptions.py`
  - `AuthConnectionError`
  - `SecureHandshakeError`
  - `ExpiredKeyError`
  - `MessageIntegrityError`
  - `SerializationError`

C references:

- `entity/c/src/c_api.c`
  - `server_secure_comm_setup(...)`: server-side secure handshake.
- `entity/c/src/c_secure_comm.c`
  - `check_handshake1_send_handshake2(...)`: decrypts handshake 1 and builds
    handshake 2.
- `entity/c/src/c_common.c`
  - `serialize_handshake(...)`
  - `parse_handshake(...)`
- `entity/c/src/c_common.h`
  - `SKEY_HANDSHAKE_1`
  - `SKEY_HANDSHAKE_2`
  - `SKEY_HANDSHAKE_3`
  - `HS_NONCE_SIZE`

Node references:

- `entity/node/accessors/node_modules/iotSecureServer.js`
  - `secureServerHelper(...)`
  - `sendHandshake2(...)`
- `entity/node/accessors/SecureCommServer.js`
  - `onClientRequest(...)`: extracts key ID and handles the cached-key path.
- `entity/node/accessors/node_modules/common.js`
  - `serializeHandshake(...)`
  - `parseHandshake(...)`

### Learning notes

Topics worth studying for this step:

- TCP server sockets and `accept()`:
  <https://docs.python.org/3/library/socket.html#socket.socket.accept>
- Why server code is usually split into "accept connection" and "handle one
  connection" pieces.
- Cache lookup and error translation: low-level cache miss vs protocol-level
  handshake failure.
- Designing symmetric protocol tests where a client helper and server helper
  validate each other.

### Expected verification command after implementation

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Documentation status:

- Step 8 is documented here.

### Step 8 implementation references

The Step 8 TCP secure server handshake layer has now been implemented.

Python files:

- `entity/python/iotauth/handshake.py`
  - `parse_handshake_1_key_id(...)`: extracts the 8-byte session key ID prefix
    from `SKEY_HANDSHAKE_1`.
  - `verify_handshake_1_and_build_handshake_2(...)`: decrypts handshake 1,
    verifies that it contains the client nonce, and builds encrypted
    handshake 2 with the server nonce plus client reply nonce.
  - `verify_handshake_3(...)`: decrypts handshake 3 and verifies that the
    client echoed the server nonce.
- `entity/python/iotauth/secure_channel.py`
  - `accept_secure(...)`: completes the server-side handshake on an already
    accepted TCP socket and returns `SecureChannel`.
  - `_lookup_session_key(...)`: looks up the requested key ID in
    `ctx.session_keys` and translates cache misses into `SecureHandshakeError`.
  - Reuses `SecureChannel`, `session_key_is_expired(...)`, `recv_frame(...)`,
    and `send_frame(...)` from previous steps.
- `entity/python/iotauth/context.py`
  - `IoTAuthContext.accept_secure(...)`: convenience method that delegates to
    `secure_channel.accept_secure(...)`.
- `entity/python/iotauth/__init__.py`
  - Exports `accept_secure`, `parse_handshake_1_key_id(...)`,
    `verify_handshake_1_and_build_handshake_2(...)`, and
    `verify_handshake_3(...)`.
- `entity/python/tests/test_handshake.py`
  - Tests key-ID extraction, short handshake 1 rejection, handshake 1
    verification, handshake 2 construction, handshake 3 verification, nonce
    mismatch handling, and client/server crypto-backed helper compatibility.
- `entity/python/tests/test_secure_channel.py`
  - Tests `accept_secure(...)` success, unknown session key ID, wrong first
    frame type, wrong third frame type, expired key handling, TCP early-close
    handling, and the context convenience method.

Implementation notes:

- Step 8 implements the cached-key server handshake path only.
- If the requested session key ID is not in `ctx.session_keys`, Python raises
  `SecureHandshakeError`.
- Server-side "request session key by key ID from Auth" remains a later step.
- `accept_secure(...)` closes the accepted socket if the handshake fails.
- `SecureChannel` is still a minimal state object. Encrypted
  `SecureChannel.send(...)` and `SecureChannel.recv(...)` are still future work.

Verification command:

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 108 tests
OK
```

## Step 9: SecureChannel message send/receive design

After Steps 7 and 8, Python can create a `SecureChannel` from either side of a
TCP connection:

- Client side: `connect_secure(ctx, key=...)`
- Server side: `accept_secure(ctx, sock)`

But the channel is still only a state object. Step 9 should make
`SecureChannel` useful by adding encrypted application-data messages:

```python
channel.send(b"hello")
reply = channel.recv()
```

This step should implement `SECURE_COMM_MSG` send/receive with sequence-number
protection. It should not yet implement a long-running server loop, examples,
asyncio, UDP, or graceful `FIN_SECURE_COMM` close behavior beyond basic local
socket close.

### Goal

At the end of Step 9, two already-handshaken Python channels should be able to
exchange encrypted bytes:

```python
client_channel.send(b"hello")
data = server_channel.recv()

server_channel.send(b"ack")
reply = client_channel.recv()
```

The application should only see plaintext bytes. The channel should handle:

- sequence-number prefixing,
- encryption/authentication,
- IoTSP framing,
- decrypt/auth verification,
- sequence-number validation,
- sequence counter updates.

### Why this comes next

Steps 7 and 8 prove both entities have the same session key. Step 9 uses that
session key for the actual protected data path.

This is the first step where the Python API behaves like the intended IoTAuth
entity API instead of only doing setup. After Step 9, the remaining work can
move up a level into listener loops and examples.

### C mental model

The C secure-message path is in `entity/c/src/c_secure_comm.c` and
`entity/c/src/c_api.c`:

```c
send_SECURE_COMM_message(...)
decrypt_received_message(...)
send_secure_message(...)
read_secure_message(...)
```

C send flow:

1. Check the session key is still valid.
2. Build plaintext as `sequence_number || application_payload`.
3. Encrypt/authenticate with the session key.
4. Increment `sent_seq_num`.
5. Send an IoTSP frame with message type `SECURE_COMM_MSG`.

C receive flow:

1. Read one IoTSP frame.
2. Require message type `SECURE_COMM_MSG`.
3. Decrypt/authenticate with the session key.
4. Parse the sequence number.
5. Require it to equal `received_seq_num`.
6. Check the session key is still valid.
7. Increment `received_seq_num`.
8. Return application plaintext after the sequence-number prefix.

### Node mental model

The Node secure-message path is in:

- `entity/node/accessors/node_modules/iotSecureSocket.js`
- `entity/node/accessors/node_modules/common.js`

Node send flow:

```javascript
serializeEncryptSessionMessage(
  {seqNum: this.writeSeqNum, data: data},
  this.sessionKey,
  this.sessionCryptoSpec
)
```

Node receive flow:

```javascript
var ret = common.parseSessionMessage(decryptedBytes);
if (ret.seqNum != this.readSeqNum) {
    return {success: false, error: "seqNum does not match"};
}
```

Python should mirror this model directly.

### Wire format

The decrypted secure message plaintext should be:

```text
sequence_number: 8 bytes, unsigned big-endian
application_payload: remaining bytes
```

The encrypted IoTSP frame should be:

```text
message_type: SECURE_COMM_MSG
payload: symmetric_encrypt_authenticate(sequence_number || application_payload)
```

Sequence numbers start at zero:

- `SecureChannel.send_sequence = 0`
- `SecureChannel.receive_sequence = 0`

After a successful send:

- encrypt and send using the current `send_sequence`,
- then increment `send_sequence` by one.

After a successful receive:

- decrypt and parse the incoming sequence number,
- require it equals the current `receive_sequence`,
- then increment `receive_sequence` by one.

### Proposed Python module changes

Step 9 should build mostly in:

```text
entity/python/iotauth/
  secure_channel.py
```

Suggested additions:

- `SecureChannel.send(data: bytes) -> None`
- `SecureChannel.recv() -> bytes`
- `SecureChannel.close() -> None` already exists, but may need stricter closed
  state handling.
- `_encrypt_secure_message(channel, data) -> bytes`
- `_decrypt_secure_message(channel, encrypted) -> bytes`
- `_serialize_secure_message(sequence, data) -> bytes`
- `_parse_secure_message(plaintext) -> tuple[int, bytes]`

If the helpers become too large, a later cleanup can move message-body helpers
into a separate `secure_messages.py`. For Step 9, keeping them near
`SecureChannel` is reasonable because the channel owns the counters.

### Proposed public API

Step 9 should make these existing channel objects useful:

```python
channel.send(b"hello")
data = channel.recv()
channel.close()
```

Behavior:

- `send(...)` accepts bytes-like data and writes one `SECURE_COMM_MSG` frame.
- `recv(...)` reads one frame and returns plaintext bytes.
- `close(...)` marks the channel closed and closes the underlying socket.

Open choice:

- We can support only `bytes` in the first implementation for clarity.
- If we support `bytearray` or `memoryview`, convert them to `bytes` at the API
  boundary.

### Error model additions

Step 9 should add the error classes already listed in the earlier error model:

- `SecureChannelClosed`: send/recv attempted after close, or socket closes
  cleanly before a complete message arrives.
- `InvalidSequenceNumberError`: decrypted sequence number does not equal the
  expected receive sequence number.

Existing errors should still be used:

- `AuthConnectionError`: socket read/write failure.
- `SerializationError`: malformed decrypted secure-message plaintext.
- `MessageIntegrityError`: decrypt/MAC/authentication failure.
- `ExpiredKeyError`: session key is expired before send or receive completes.
- `SecureHandshakeError`: should not normally be used in Step 9 because the
  handshake is already done.

Open choice:

- `recv_frame(...)` currently raises `AuthConnectionError` on early close.
  Step 9 can either let that bubble out or translate it to
  `SecureChannelClosed`. Translating inside `SecureChannel.recv()` is nicer for
  channel users.

### Session-key validity

Step 9 should reuse:

```python
session_key_is_expired(channel.session_key)
```

Suggested behavior:

- Check before `send(...)`.
- Check after decrypting and before accepting a received message.
- Raise `ExpiredKeyError` if expired.

C checks key validity on both send and receive paths, so Python should do the
same.

### Sequence-number rules

Send rules:

- Use current `send_sequence`.
- Encode it as 8-byte unsigned big-endian.
- Encrypt and send.
- Increment only after successful `send_frame(...)`.

Receive rules:

- Decrypt first.
- Parse the first 8 bytes as unsigned big-endian.
- If it does not equal `receive_sequence`, raise
  `InvalidSequenceNumberError`.
- Increment only after the sequence number is accepted.

Overflow rule:

- The sequence number must fit in 8 bytes.
- If `send_sequence > 0xFFFFFFFFFFFFFFFF`, raise `InvalidSequenceNumberError`
  or `SerializationError`. `InvalidSequenceNumberError` is clearer at the
  channel level.

### Close behavior

Step 9 can keep close behavior simple:

```python
channel.close()
```

Expected behavior:

- If already closed, do nothing.
- Close the underlying socket if it has `close()`.
- Set `closed=True`.
- `send(...)` and `recv(...)` after close raise `SecureChannelClosed`.

`FIN_SECURE_COMM` can remain a later milestone. The C and Node code include
`FIN_SECURE_COMM`, but the current first milestone needs working TCP
application data before graceful protocol close.

### Tests to add

Secure message serialization tests:

- Serialize sequence `0` and payload `b"hello"` into `8-byte-seq || payload`.
- Parse secure message plaintext back into `(sequence, payload)`.
- Reject plaintext shorter than 8 bytes.
- Reject sequence numbers that do not fit in 8 bytes.

Channel send tests:

- `channel.send(b"hello")` sends a `SECURE_COMM_MSG` frame.
- Sent frame decrypts to sequence `0` plus payload `b"hello"`.
- `send_sequence` increments after successful send.
- Failed socket write does not increment `send_sequence`.
- Sending after close raises `SecureChannelClosed`.
- Sending with expired key raises `ExpiredKeyError`.

Channel receive tests:

- `channel.recv()` decrypts a valid `SECURE_COMM_MSG` and returns payload.
- `receive_sequence` increments after successful receive.
- Wrong message type raises `SerializationError` or `SecureChannelClosed`
  depending on the chosen error boundary.
- Sequence mismatch raises `InvalidSequenceNumberError`.
- Tampered encrypted payload raises `MessageIntegrityError`.
- Receiving after close raises `SecureChannelClosed`.
- Receiving with expired key raises `ExpiredKeyError`.

Round-trip tests:

- Create two `SecureChannel` objects with connected fake sockets or a socket
  pair.
- Send from client channel, receive on server channel.
- Send from server channel, receive on client channel.
- Verify both channels maintain independent send and receive counters.

### Step 9 repo references

Python references from previous steps:

- `entity/python/iotauth/secure_channel.py`
  - `SecureChannel`
  - `connect_secure(...)`
  - `accept_secure(...)`
  - `session_key_is_expired(...)`
- `entity/python/iotauth/crypto.py`
  - `symmetric_encrypt_authenticate(...)`
  - `symmetric_decrypt_authenticate(...)`
- `entity/python/iotauth/messages.py`
  - `MessageType.SECURE_COMM_MSG`
  - `MessageType.FIN_SECURE_COMM`
  - `IoTSPFrame`
- `entity/python/iotauth/transports/tcp.py`
  - `send_frame(...)`
  - `recv_frame(...)`
- `entity/python/iotauth/serialization/binary.py`
  - `encode_uint_be(...)`
  - `decode_uint_be(...)`
- `entity/python/iotauth/exceptions.py`
  - Add `SecureChannelClosed`.
  - Add `InvalidSequenceNumberError`.
  - Reuse `ExpiredKeyError`.
  - Reuse `MessageIntegrityError`.

C references:

- `entity/c/src/c_secure_comm.c`
  - `send_SECURE_COMM_message(...)`
  - `decrypt_received_message(...)`
- `entity/c/src/c_api.c`
  - `send_secure_message(...)`
  - `read_secure_message(...)`
- `entity/c/src/c_api.h`
  - `SEQ_NUM_SIZE`
  - `MAX_SECURE_COMM_MSG_LENGTH`

Node references:

- `entity/node/accessors/node_modules/iotSecureSocket.js`
  - `IoTSecureSocket.prototype.send(...)`
  - `IoTSecureSocket.prototype.receive(...)`
- `entity/node/accessors/node_modules/common.js`
  - `SEQ_NUM_SIZE`
  - `serializeEncryptSessionMessage(...)`
  - `parseDecryptSessionMessage(...)`
  - `parseSessionMessage(...)`

### Learning notes

Topics worth studying for this step:

- Why authenticated encryption or encrypt-then-MAC protects message integrity.
- Replay protection with monotonically increasing sequence numbers.
- Big-endian integer encoding as a wire-format convention.
- State machines: why counters should only update after a successful operation.
- Designing APIs that translate low-level socket failures into domain-specific
  channel errors.

### Expected verification command after implementation

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Documentation status:

- Step 9 is documented here.

### Step 9 implementation references

The Step 9 secure-channel message send/receive layer has now been implemented.

Python files:

- `entity/python/iotauth/secure_channel.py`
  - `SecureChannel.send(...)`: encrypts one application payload, wraps it in a
    `SECURE_COMM_MSG` IoTSP frame, writes it to the socket, and increments
    `send_sequence` after a successful write.
  - `SecureChannel.recv(...)`: reads one `SECURE_COMM_MSG` frame, decrypts and
    verifies it, validates the sequence number, increments `receive_sequence`,
    and returns application plaintext bytes.
  - `SecureChannel.close(...)`: now ignores socket close `OSError`s and marks
    the channel closed.
  - `_serialize_secure_message(...)`: serializes
    `8-byte sequence || application payload`.
  - `_parse_secure_message(...)`: parses decrypted secure-message plaintext.
  - `_encrypt_secure_message(...)`: encrypts/authenticates a secure message
    body with the channel's session key.
  - `_decrypt_secure_message(...)`: decrypts/authenticates a secure message
    body and validates the receive sequence number.
  - `SEQ_NUM_SIZE`: set to 8 bytes to match C and Node wire format.
  - `MAX_SEQUENCE_NUMBER`: maximum 8-byte unsigned sequence value.
- `entity/python/iotauth/exceptions.py`
  - Added `SecureChannelClosed`.
  - Added `InvalidSequenceNumberError`.
- `entity/python/iotauth/__init__.py`
  - Exports `SecureChannelClosed` and `InvalidSequenceNumberError`.
- `entity/python/tests/test_secure_channel.py`
  - Tests secure-message serialization and parsing.
  - Tests channel send frame type, encryption, and sequence increment.
  - Tests failed sends do not increment sequence numbers.
  - Tests receive decrypts valid messages and increments receive sequence.
  - Tests sequence mismatch, tampering, expired keys, closed channel behavior,
    wrong message type, early close translation, and channel round trips.

Implementation notes:

- Secure message plaintext is `sequence_number || payload`, where the sequence
  number is an 8-byte unsigned big-endian integer.
- `send_sequence` increments only after `send_frame(...)` succeeds.
- `receive_sequence` increments only after the decrypted sequence number matches
  the expected value.
- `SecureChannel.recv(...)` translates TCP early close into
  `SecureChannelClosed`.
- `FIN_SECURE_COMM` is still not implemented. `close(...)` is local socket
  cleanup only.

Verification command:

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 123 tests
OK
```

## Step 10: high-level client/server API design

After Step 9, the low-level protocol pieces are usable:

- `IoTAuthContext.from_config(...)`
- `ctx.request_session_keys(...)`
- `ctx.connect_secure(...)`
- `ctx.accept_secure(...)`
- `SecureChannel.send(...)`
- `SecureChannel.recv(...)`

Step 10 should make those pieces easier for application developers to use by
adding high-level client and server wrappers. These wrappers should not invent
new wire behavior. Their job is to call the existing lower-level APIs in the
right order.

This is the difference between "all protocol tools exist" and "the Python API
feels pleasant to use."

### Goal

At the end of Step 10, client code should look like this:

```python
from iotauth import IoTAuthContext, SecureClient

ctx = IoTAuthContext.from_config("entity/python/examples/configs/client.config")

with SecureClient(ctx) as client:
    client.connect()
    client.send(b"hello")
    reply = client.recv()
```

Server code should be able to handle one accepted connection like this:

```python
from iotauth import IoTAuthContext, SecureServer

ctx = IoTAuthContext.from_config("entity/python/examples/configs/server.config")
server = SecureServer(ctx)

channel = server.serve_once()
data = channel.recv()
channel.send(b"ack: " + data)
```

The first server API should prefer `serve_once()` over `serve_forever()`.
`serve_once()` is easier to test, easier to understand, and enough for the first
examples.

### Why this comes next

The current API is powerful but still manual. A user must understand the whole
workflow:

1. Load context.
2. Request session keys.
3. Pick a session key.
4. Resolve the target server.
5. Connect securely.
6. Send and receive on the channel.
7. Close the channel.

`SecureClient` should own that client-side workflow.

On the server side, a user must currently:

1. Create a listening socket.
2. Bind and listen.
3. Accept a TCP connection.
4. Call `ctx.accept_secure(...)`.
5. Remember to close everything.

`SecureServer` should own that server-side setup for the common case.

### C mental model

In C, application code does not normally call every tiny helper directly. It
uses higher-level API functions around the lower-level protocol operations:

```c
init_SST(...)
send_session_key_req_via_TCP(...)
secure_connect_to_server_with_socket(...)
server_secure_comm_setup(...)
send_secure_message(...)
read_secure_message(...)
```

Python Step 10 should provide the same kind of ergonomic layer, but in a
Pythonic object style.

The lower-level Python functions should remain public and testable. The new
classes simply organize them for normal application code.

### Proposed Python modules

Step 10 should add:

```text
entity/python/iotauth/
  client.py
  server.py
```

Suggested responsibilities:

- `client.py`
  - Define `SecureClient`.
  - Request session keys when needed.
  - Pick a session key.
  - Connect to the configured or overridden target.
  - Delegate `send(...)`, `recv(...)`, and `close(...)` to `SecureChannel`.
  - Support context-manager usage.
- `server.py`
  - Define `SecureServer`.
  - Create, bind, listen, and close a TCP server socket.
  - Accept one connection.
  - Call `ctx.accept_secure(...)`.
  - Return a `SecureChannel`.
  - Support context-manager usage.

### SecureClient API

Proposed first version:

```python
class SecureClient:
    def __init__(
        self,
        ctx: IoTAuthContext,
        *,
        key: SessionKey | None = None,
        purpose: dict[str, object] | str | None = None,
        host: str | None = None,
        port: int | None = None,
        timeout: float | None = 5.0,
    ):
        ...

    def connect(self) -> SecureChannel:
        ...

    def send(self, data: bytes) -> None:
        ...

    def recv(self) -> bytes:
        ...

    def close(self) -> None:
        ...

    def __enter__(self) -> SecureClient:
        ...

    def __exit__(self, exc_type, exc, tb) -> None:
        ...
```

Behavior:

- If a `key` is provided, use it directly.
- If no `key` is provided, call `ctx.request_session_keys(...)` and use the
  first returned key.
- `connect()` should call `ctx.connect_secure(...)`.
- `send(...)` and `recv(...)` should require an active channel.
- `close()` should close the active channel if one exists.
- `__exit__` should always close the channel.

Open choice:

- Should `__enter__` call `connect()` automatically?
- Recommended first behavior: `__enter__` returns `self`, and the user calls
  `connect()` explicitly. This avoids surprising network I/O just because a
  `with` block starts.

### SecureServer API

Proposed first version:

```python
class SecureServer:
    def __init__(
        self,
        ctx: IoTAuthContext,
        *,
        host: str | None = None,
        port: int | None = None,
        backlog: int = 5,
        timeout: float | None = 5.0,
    ):
        ...

    def listen(self) -> None:
        ...

    def serve_once(self) -> SecureChannel:
        ...

    def close(self) -> None:
        ...

    def __enter__(self) -> SecureServer:
        ...

    def __exit__(self, exc_type, exc, tb) -> None:
        ...
```

Behavior:

- If `host` and `port` are provided, bind to those.
- If not provided, use `ctx.config.targets[0]` for now.
- `listen()` creates and starts the listening socket.
- `serve_once()` calls `listen()` if needed, accepts one TCP connection, then
  calls `ctx.accept_secure(client_socket)`.
- `close()` closes the listening socket.

Open choice:

- A server config may need a more explicit "bind address" field later. Current
  config uses `entity.server.ip.address` and `entity.server.port.number`, which
  is enough for first examples.

### Error behavior

`SecureClient` should reuse lower-level errors:

- `ConfigError`: no target or invalid target override.
- `AuthConnectionError`: TCP connect/read/write failure.
- `AuthProtocolError`: Auth session-key request failure.
- `SecureHandshakeError`: secure handshake failure.
- `SecureChannelClosed`: send/recv before connect or after close.
- `ExpiredKeyError`: expired session key.

`SecureServer` should use:

- `ConfigError`: no bind target or invalid bind parameters.
- `AuthConnectionError`: listening socket, accept, read, or write failure.
- `SecureHandshakeError`: secure handshake failure.
- `SecureChannelClosed`: operations after close if applicable.

Open choice:

- Raw `OSError` from `socket.bind(...)`, `listen(...)`, or `accept(...)` should
  probably be translated into `AuthConnectionError`, even though the name says
  "Auth". We may later rename or add a more generic `TransportError`, but for
  now reusing `AuthConnectionError` keeps the error model small.

### Testing plan

Client tests:

- `SecureClient.connect()` uses a provided session key without requesting one.
- `SecureClient.connect()` requests session keys when no key is provided.
- `SecureClient.connect()` stores the returned `SecureChannel`.
- `SecureClient.send(...)` delegates to the active channel.
- `SecureClient.recv(...)` delegates to the active channel.
- `SecureClient.send(...)` before connect raises `SecureChannelClosed`.
- `SecureClient.close()` closes the active channel.
- Context manager calls `close()` on exit.

Server tests:

- `SecureServer.listen()` binds and listens once.
- `SecureServer.serve_once()` accepts one socket and calls `ctx.accept_secure`.
- `SecureServer.serve_once()` returns the accepted `SecureChannel`.
- `SecureServer.close()` closes the listening socket.
- Context manager calls `close()` on exit.
- Socket setup failures are translated into `AuthConnectionError`.

Integration-style unit tests:

- Use fake sockets to prove `SecureClient` calls `ctx.connect_secure(...)`.
- Use fake listening socket to prove `SecureServer` calls
  `ctx.accept_secure(...)`.

Real end-to-end integration with actual TCP sockets can wait for the example
step.

### Step 10 repo references

Python references from previous steps:

- `entity/python/iotauth/context.py`
  - `IoTAuthContext.request_session_keys(...)`
  - `IoTAuthContext.connect_secure(...)`
  - `IoTAuthContext.accept_secure(...)`
- `entity/python/iotauth/secure_channel.py`
  - `SecureChannel`
  - `connect_secure(...)`
  - `accept_secure(...)`
  - `SecureChannel.send(...)`
  - `SecureChannel.recv(...)`
  - `SecureChannel.close(...)`
- `entity/python/iotauth/config.py`
  - `TargetServer`
  - `EntityConfig.targets`
- `entity/python/iotauth/exceptions.py`
  - `AuthConnectionError`
  - `ConfigError`
  - `SecureChannelClosed`
  - `SecureHandshakeError`

C references:

- `entity/c/src/c_api.c`
  - high-level secure connect, secure server setup, send, and read APIs.
- `entity/c/examples/server_client_example`
  - intended simple client/server application shape.

Node references:

- `entity/node/accessors/SecureCommClient.js`
  - application-facing client accessor behavior.
- `entity/node/accessors/SecureCommServer.js`
  - application-facing server accessor behavior.
- `entity/node/accessors/node_modules/iotSecureClient.js`
  - lower-level client connector that `SecureClient` conceptually wraps.
- `entity/node/accessors/node_modules/iotSecureServer.js`
  - lower-level server handshake logic that `SecureServer` conceptually wraps.

### Learning notes

Topics worth studying for this step:

- Python context managers:
  <https://docs.python.org/3/reference/datamodel.html#context-managers>
- Object composition: wrapping a lower-level object instead of inheriting from
  it.
- API ergonomics: designing a friendly front door while keeping lower-level
  escape hatches available.
- Socket server lifecycle: create, bind, listen, accept, close.

### Expected verification command after implementation

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Documentation status:

- Step 10 is documented here.

### Step 10 implementation references

The Step 10 high-level client/server API layer has now been implemented.

Python files:

- `entity/python/iotauth/client.py`
  - `SecureClient`: high-level client wrapper around `IoTAuthContext`,
    session-key request, `ctx.connect_secure(...)`, and `SecureChannel`.
  - `SecureClient.connect(...)`: uses a provided session key when available, or
    requests session keys and connects with the first returned key.
  - `SecureClient.send(...)`: delegates to the active channel.
  - `SecureClient.recv(...)`: delegates to the active channel.
  - `SecureClient.close(...)`: closes the active channel.
  - `SecureClient.__enter__(...)` / `__exit__(...)`: context-manager support.
- `entity/python/iotauth/server.py`
  - `SecureServer`: high-level server wrapper around listening socket setup,
    `accept()`, and `ctx.accept_secure(...)`.
  - `SecureServer.listen(...)`: creates, binds, and listens on a TCP socket.
  - `SecureServer.serve_once(...)`: accepts one TCP connection and returns the
    secure channel created by `ctx.accept_secure(...)`.
  - `SecureServer.close(...)`: closes the listening socket.
  - `SecureServer.__enter__(...)` / `__exit__(...)`: context-manager support.
- `entity/python/iotauth/__init__.py`
  - Exports `SecureClient`.
  - Exports `SecureServer`.
- `entity/python/tests/test_client.py`
  - Tests provided-key connect, auto session-key request, channel storage,
    send/recv delegation, send before connect, close, and context-manager
    cleanup.
- `entity/python/tests/test_server.py`
  - Tests listen/bind behavior, host/port override, `serve_once(...)`
    delegation, close behavior, context-manager cleanup, bind failure
    translation, and accept failure translation.

Implementation notes:

- `SecureClient.__enter__()` does not connect automatically. The user still
  calls `connect()` explicitly, which avoids hidden network I/O when entering a
  `with` block.
- `SecureClient` keeps lower-level APIs available. It simply owns the common
  client workflow.
- `SecureServer` starts with `serve_once()` only. A full `serve_forever()` loop
  remains future work.
- `SecureServer` translates listening socket setup and accept failures into
  `AuthConnectionError`.
- `SecureServer` currently binds to the first configured target when host/port
  are not provided.

Verification command:

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

Current result:

```text
Ran 136 tests
OK
```

## Pythonic Restructure (Refactor Phase)

After completing the initial step-by-step implementation, the `iotauth` codebase was restructured. Originally, the code was planned and written following a C-style background, where declarations and implementations were artificially separated into many small files and nested directories (similar to header and source files). To align with Python best practices, we moved to a flatter, more cohesive module structure.

### Main Package Consolidation

- **`protocol.py`**: The previously separate `messages.py` (for base IoTSP messages) and `auth_messages.py` (for Auth payload builders) were merged into a single `protocol.py` module. Separating them was an unnecessary artifact of C-style design; grouping them makes it much easier to import and manage protocol logic.
- **Flattened Directories**: The nested `serialization/` and `transports/` directories (which were going to contain `binary.py`, `tcp.py`, etc.) were flattened into single modules: `serialization.py` and `transports.py`. This avoids overly deep imports like `from iotauth.serialization.binary import ...` in favor of simpler, flatter imports.

### Test Suite Consolidation

To mirror the newly flattened main package, the test suite was also heavily consolidated to improve maintainability and remove C-style code fragmentation:

- **Shared Helpers**: Extracted common test fixtures (like `FakeSocket` and `make_session_key`) into `tests/helpers.py`.
- **Protocol Tests**: Merged `test_messages.py` and `test_auth_messages.py` into a unified `test_protocol.py`.
- **Wire Tests**: Merged `test_serialization.py` and `test_tcp_transport.py` into `test_wire.py`.
- **Context & Wrapper Tests**: Merged `test_credentials.py` into `test_context.py` and merged `test_client.py` with `test_server.py` into `test_wrappers.py`.
- **Verbosity & Output**: Updated the test runner to use `verbosity=2` and introduced a custom `run_tests.py` script that formats standard `unittest` output into readable natural language sentences.

This restructuring reduced the test suite from 14 scattered files down to 9 highly focused modules, making the entire architecture flatter, more Pythonic, and significantly easier to extend.
