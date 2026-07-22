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
python3 pyServer.py configs/pyServer.config --accept-timeout 30

# Allow up to 10 seconds for the secure handshake
python3 pyServer.py --handshake-timeout 10 configs/pyServer.config

# Limit server to processing 3 messages per connection
python3 pyServer.py configs/pyServer.config -n/--max-messages 3

# Combine timeout and max-messages flags
python3 pyServer.py --accept-timeout 30 --handshake-timeout 10 --max-messages 5 configs/pyServer.config
```

## Client options (`pyClient.py`)

The client allows five seconds for Auth communication, the outbound TCP
connection, and the secure handshake by default. Override that shared limit in
seconds with `--timeout`:

```bash
python3 pyClient.py configs/pyClient.config --timeout 10
```
