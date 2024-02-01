# Python API
---
This directory includes Python API for entity server and File System Manager

**load_config()**

- load_config() is a function to load the config file

**get_session_key()**

- get_session_key() is a function to get secure session key from Auth.

# Example

- We use entity client in '$iotauth/entity/c/examples' and entity server in `$iotauth/examples/filesharing`.

- According to indication for C example, we turn on two different terminal at `$iotauth/entity/c/examples/build`, `$iotauth/examples/filesharing`, and Auth on the third terminal.

Execute

`$./entity_client ../c_client.config`

`$python3 filesystem_server.py server.config` (Here, we have to change the path for private key and public key in config file.)

# TODOs

- Add Python API code for File System Manager to communicate with uploader and downloader using secure session key.