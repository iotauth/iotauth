# IoTAuth Python API

This directory contains the Python entity-side API for IoTAuth. The code here is
intended to give Python programs a small, readable interface for requesting
session keys from Auth, completing the IoTSP secure handshake, and sending or
receiving protected messages.

The step-by-step learning and implementation notes were moved to
[API_implementation_REDME.md](./API_implementation_REDME.md).

For developer-facing class, function, and usage details, see
[API_REFERENCE.md](./API_REFERENCE.md).

## Current scope

The Python API currently includes:

- configuration parsing for entity settings
- credential loading for private keys, certificates, and trusted CAs
- IoTSP frame serialization and parsing
- Auth message serialization and parsing
- TCP helpers for frame-based transport
- cryptographic helpers for RSA, AES-CBC, AES-GCM, and HMAC
- session key and distribution key models
- session key cache management
- Auth session-key request workflow
- secure handshake helpers
- encrypted secure channel send and receive logic
- high-level `SecureClient` and `SecureServer` wrappers

## Directory structure

```text
entity/python/
  README.md
  API_REFERENCE.md
  API_implementation_REDME.md
  entity_server.py
  iotauth/
    __init__.py
    auth_service.py
    client.py
    config.py
    context.py
    credentials.py
    crypto.py
    exceptions.py
    handshake.py
    keys.py
    protocol.py
    secure_channel.py
    serialization.py
    server.py
    transports.py
  tests/
    test_auth_messages.py
    test_auth_service.py
    test_client.py
    test_config.py
    test_context.py
    test_credentials.py
    test_crypto.py
    test_handshake.py
    test_keys.py
    test_messages.py
    test_secure_channel.py
    test_serialization.py
    test_server.py
    test_tcp_transport.py
```

## File purpose

### Top-level files

| File | Purpose |
| --- | --- |
| `README.md` | Main guide to the Python directory structure and file responsibilities. |
| `API_REFERENCE.md` | Developer-facing reference for public classes, functions, examples, and exceptions. |
| `API_implementation_REDME.md` | Detailed step-by-step API design, theory, implementation notes, and references. |
| `entity_server.py` | Existing legacy Python server file. It is currently outside the new API work. |

### Package files

| File | Purpose |
| --- | --- |
| `iotauth/__init__.py` | Public package exports, so callers can import the main API objects from `iotauth`. |
| `iotauth/auth_service.py` | Connects to Auth and performs the session-key request workflow. |
| `iotauth/client.py` | High-level client API for connecting to Auth, requesting keys, and opening secure peer connections. |
| `iotauth/config.py` | Loads and validates entity configuration files into typed Python dataclasses. |
| `iotauth/context.py` | Shared runtime object that combines config, credentials, key cache, Auth access, and secure connection helpers. |
| `iotauth/credentials.py` | Loads private keys, certificates, and trusted CA certificates from disk. |
| `iotauth/crypto.py` | Contains low-level cryptographic helpers and higher-level wrappers used by Auth and secure channels. |
| `iotauth/exceptions.py` | Central exception hierarchy for configuration, credentials, serialization, Auth, crypto, and secure-channel errors. |
| `iotauth/handshake.py` | Builds and parses secure handshake payloads for `SKEY_HANDSHAKE_1`, `SKEY_HANDSHAKE_2`, and `SKEY_HANDSHAKE_3`. |
| `iotauth/keys.py` | Defines session key and distribution key models plus the in-memory session key cache. |
| `iotauth/protocol.py` | Combines IoTSP message types, frame containers, and Auth protocol payload serialization and parsing helpers. |
| `iotauth/secure_channel.py` | Implements the secure handshake and the encrypted `SecureChannel` send/receive API. |
| `iotauth/serialization.py` | Binary serialization primitives for variable-length integers and multi-byte integers. |
| `iotauth/server.py` | High-level server API for listening for peers and accepting secure connections. |
| `iotauth/transports.py` | Provides TCP connect, listen, accept, send-frame, receive-frame, and socket-cleanup helpers. |

### Tests

The `tests/` directory mirrors the package modules. Each test file focuses on
one API layer so changes can be checked in small pieces.

| File | Purpose |
| --- | --- |
| `tests/test_auth_messages.py` | Tests Auth payload builders and parsers. |
| `tests/test_auth_service.py` | Tests Auth session-key request behavior and error handling. |
| `tests/test_client.py` | Tests the high-level `SecureClient` wrapper. |
| `tests/test_config.py` | Tests configuration parsing and validation. |
| `tests/test_context.py` | Tests the shared `IoTAuthContext` convenience API. |
| `tests/test_credentials.py` | Tests credential loading helpers. |
| `tests/test_crypto.py` | Tests cryptographic helper behavior. |
| `tests/test_handshake.py` | Tests secure handshake payload encoding and decoding. |
| `tests/test_keys.py` | Tests key models and key cache behavior. |
| `tests/test_messages.py` | Tests IoTSP message type and frame helpers. |
| `tests/test_secure_channel.py` | Tests secure handshake and encrypted channel behavior. |
| `tests/test_serialization.py` | Tests binary serialization helpers. |
| `tests/test_server.py` | Tests the high-level `SecureServer` wrapper. |
| `tests/test_tcp_transport.py` | Tests TCP transport helpers. |

## Running tests

From the repository root:

```bash
PYTHONPATH=entity/python PYTHONDONTWRITEBYTECODE=1 entity/python/.venv/bin/python -m unittest discover -s entity/python/tests
```

If the virtual environment has not been created yet:

```bash
python3 -m venv entity/python/.venv
entity/python/.venv/bin/python -m pip install --upgrade pip
entity/python/.venv/bin/python -m pip install cryptography
```

## Notes for future work

The implementation diary in `API_implementation_REDME.md` is still the best
place for planned steps and deeper explanations. This README should stay short
and practical: what exists, where it lives, and what each file is responsible
for.
