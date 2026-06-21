# IoTAuth Python API

This directory contains the Python entity-side API for IoTAuth. The code here is
intended to give Python programs a small, readable interface for requesting
session keys from Auth, completing the IoTSP secure handshake, and sending or
receiving protected messages.


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

These are the high-level directories and their purposes:

- **`iotauth/`**: The core Python API package. This is what developers install and import into their own applications to request keys and create secure channels.
- **`examples/`**: Working examples of Python servers and clients using the `iotauth` API. See [`examples/README.md`](examples/README.md) for details on running them.
- **`tests/`**: The automated test suite for the Python API.

For deep API documentation, consult [API_REFERENCE.md](API_REFERENCE.md). 
> TO DO :- add API references to the iotauth website and link the reference.

## Configuration (.toml)

The Python API uses **TOML** (`.toml`) files for entity configuration. 
If you are new to TOML, you can read the official quick-start guide and specification at [toml.io](https://toml.io/en/).

## Installation and Running

Before running tests or examples, create a virtual environment and install the package locally:

```bash
cd entity/python
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

This installs the `iotauth` package in editable mode. You **do not** need to mess with `PYTHONPATH` as long as your virtual environment is activated.

### Running tests

To run the full test suite with natural-language output (e.g. `Testing [capability] ... passed`):

```bash
python run_all_tests.py
```

To run an individual test file, pass its path:

```bash
python run_all_tests.py tests/test_secure_channel.py
```



### Running examples

For detailed instructions on how to run the example server and client, including how to specify configuration file paths and use timeout arguments, please see the [Examples README](examples/README.md).


## Contributing

### Code style

This directory uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.

Install:
```bash
brew install ruff
# or
pip install ruff
```

Check for issues:
```bash
ruff check .
```

Auto-fix and format:
```bash
ruff check --fix .
ruff format .
```

Ruff is configured in `pyproject.toml`. All contributions should pass `ruff check .` with no errors before submitting a pull request.
