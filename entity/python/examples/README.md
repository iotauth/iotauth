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
| `README.md` | This file. Contains usage instructions for the example scripts. |
| `pyClient.py` | A high-level client script that connects to the Auth server to request session keys, performs a secure handshake with the peer server, and sequentially sends encrypted payloads while waiting for replies. |
| `pyServer.py` | A high-level server script that listens for peer connections, verifies the secure handshake, and securely echoes received payloads back to the client. |
| `configs/` | Directory containing the `.config` files that define credentials, database paths, and networking settings for the entities. |

## Usage

Both the client and the server require a configuration file path to be passed as a **positional argument**.

```bash
# Run the server
python3 pyServer.py configs/pyServer.config

# Run the client
python3 pyClient.py configs/pyClient.config
```

## Server Timeout Configurations

The `pyServer.py` script also supports an optional timeout flag. By default, the server will wait up to 60 seconds for a client connection and the subsequent secure handshake. You can override this using the `-to` (timeout) flag, along with `-m` (minutes) or `-s` (seconds).

Python's `argparse` is flexible, so you can place the configuration file path anywhere in the command (before or after the flags), as long as it is not immediately after a flag that requires a value:

```bash
# Config path first
python3 pyServer.py configs/pyServer.config -to 5 -m

# Config path last
python3 pyServer.py -to 5 -m configs/pyServer.config

# Config path in the middle
python3 pyServer.py -m configs/pyServer.config -to 5
```
