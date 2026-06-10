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
