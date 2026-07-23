# IoTAuth Python Examples

This directory contains the example scripts for running an IoTAuth Python Client and Server.

## Directory Structure & Files

```text
examples/
  README.md
  py_client.py
  py_server.py
  configs/
```

| File / Folder | Description |
| --- | --- |
| [`README.md`](README.md) | This file. Contains usage instructions for the example scripts. |
| [`py_client.py`](py_client.py) | A high-level client script that connects to the Auth server to request session keys, performs a secure handshake with the peer server, and sequentially sends encrypted payloads while waiting for replies. |
| [`py_server.py`](py_server.py) | A high-level server script that listens for peer connections, verifies the secure handshake, receives encrypted payloads from the client, and sends back numbered response messages (`"Hello client"`, `"Hello client 2"`, etc.). |
| [`configs/`](configs) | Directory containing the `.config` files that specify paths to entity credentials/certificates and define networking settings for the entities. |

## Set Up the Python Environment

Create a virtual environment and install the `iotauth` package in editable mode before running the examples.
Run these commands from the repository root:

```bash
cd entity/python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cd examples
```

The final `cd examples` leaves the terminal in the directory expected by the commands in this README.

For later sessions, reactivate the existing environment instead of creating it again:

```bash
cd entity/python
source .venv/bin/activate
cd examples
```

Run `deactivate` when you are finished.

## Configuration File Formats

The Python API accepts both the C-style dotted properties format (`key=value`) and Node-style JSON configuration files.

`generateAll.sh` does not generate dedicated Python config files.
It generates the credentials used by the examples and the Node-style JSON configs under `entity/node/example_entities/configs/`.
The `configs/py_client.config` and `configs/py_server.config` files in this directory are checked-in C-style example fixtures.

Choose whichever format best fits your application:

- Use the checked-in Python fixtures or copy another C-style properties config and adapt its entity settings.
- Use or copy a generated Node-style JSON config.
- In either case, update the configured credential and key paths according to the format-specific path anchor described below.

Relative credential and key paths use different anchors:

| Format | Relative path anchor |
| --- | --- |
| C-style properties | The directory containing the config file. |
| Node-style JSON | The current working directory from which the Python process is started. |

Absolute paths work in both formats.

## Usage

Both the client and the server require a configuration file path to be passed as a **positional argument**.

```bash
# Run the server
python3 py_server.py configs/py_server.config

# Run the client
python3 py_client.py configs/py_client.config
```

## Server Options (`py_server.py`)

The `py_server.py` script supports optional command-line flags to control timeouts and message limits:

### Accept timeout (`--accept-timeout`)
By default, the server waits indefinitely for a client connection. Set `--accept-timeout` to limit that wait in seconds.

### Handshake timeout (`--handshake-timeout`)
After accepting a connection, the server allows five seconds for the secure handshake by default. Set `--handshake-timeout` to override that limit in seconds.

### Maximum Messages (`-n` / `--max-messages`)
By default, the server continues processing messages indefinitely for a connected client (`0` = unlimited). You can limit the maximum number of messages processed per connection before closing the channel using the `-n` or `--max-messages` flag.

### Argument Flexibility
Python's `argparse` is flexible, so you can place the configuration file path anywhere in the command (before or after the flags), as long as it is not immediately after a flag that requires a value:

```bash
# Wait up to 30 seconds for a client connection
python3 py_server.py configs/py_server.config --accept-timeout 30

# Allow up to 10 seconds for the secure handshake
python3 py_server.py --handshake-timeout 10 configs/py_server.config

# Limit server to processing 3 messages per connection
python3 py_server.py configs/py_server.config -n/--max-messages 3

# Combine timeout and max-messages flags
python3 py_server.py --accept-timeout 30 --handshake-timeout 10 --max-messages 5 configs/py_server.config
```

## Client options (`py_client.py`)

The client allows five seconds for Auth communication, the outbound TCP
connection, and the secure handshake by default. Override that shared limit in
seconds with `--timeout`:

```bash
python3 py_client.py configs/py_client.config --timeout 10
```
