# IoTAuth Python Examples

This directory contains the example scripts for running an IoTAuth Python Client and Server.

## Directory Structure & Files

```text
examples/
  README.md
  pyClient.py
  pyServer.py
  configs/
```

| File / Folder | Description |
| --- | --- |
| [`README.md`](README.md) | This file. Contains usage instructions for the example scripts. |
| [`pyClient.py`](pyClient.py) | A high-level client script that connects to the Auth server to request session keys, performs a secure handshake with the peer server, and sequentially sends encrypted payloads while waiting for replies. |
| [`pyServer.py`](pyServer.py) | A high-level server script that listens for peer connections, verifies the secure handshake, receives encrypted payloads from the client, and sends back numbered response messages (`"Hello client"`, `"Hello client 2"`, etc.). |
| [`configs/`](configs) | Directory containing the `.config` files that specify paths to entity credentials/certificates and define networking settings for the entities. |

## Usage

Both the client and the server require a configuration file path to be passed as a **positional argument**.

```bash
# Run the server
python3 pyServer.py configs/pyServer.config

# Run the client
python3 pyClient.py configs/pyClient.config
```

## Server Options (`pyServer.py`)

The `pyServer.py` script supports optional command-line flags to control timeouts and message limits:

### Timeout (`-to` / `--timeout`)
By default, the server will wait up to 60 seconds for a client connection and the subsequent secure handshake. You can override this using the `-to` or `--timeout` flag, along with `-m` / `--minutes` or `-s` / `--seconds`.

### Maximum Messages (`-n` / `--max-messages`)
By default, the server continues processing messages indefinitely for a connected client (`0` = unlimited). You can limit the maximum number of messages processed per connection before closing the channel using the `-n` or `--max-messages` flag.

### Argument Flexibility
Python's `argparse` is flexible, so you can place the configuration file path anywhere in the command (before or after the flags), as long as it is not immediately after a flag that requires a value:

```bash
# Set a 5-minute timeout with config path first
python3 pyServer.py configs/pyServer.config -to/--timeout 5 -m/--minutes

# Set a 5-minute timeout with config path last
python3 pyServer.py -to/--timeout 5 -m/--minutes configs/pyServer.config

# Limit server to processing 3 messages per connection
python3 pyServer.py configs/pyServer.config -n/--max-messages 3

# Combine timeout and max-messages flags
python3 pyServer.py -to/--timeout 30 -s/--seconds -n/--max-messages 5 configs/pyServer.config
```
