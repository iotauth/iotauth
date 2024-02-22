# Python API
---
This directory includes Python API for SST's entity server and File System Manager, which was introduced in our paper [[Mid4CC '23](https://dl.acm.org/doi/10.1145/3631309.3632832)].

**load_config()**
- `load_config()` is a function to load the config file.

**get_session_key()**
- `get_session_key()` is a function to get a secure session key from Auth.

# Example

- We use entity client in '$iotauth/entity/c/examples' and entity server in `$iotauth/examples/filesharing`.
- According to indication for C example, we turn on two different terminal at `$iotauth/entity/c/examples/build`, `$iotauth/examples/filesharing`, and Auth on the third terminal.

- To execute C entity client:
`$./entity_client ../c_client.config`

- To execute Python entity server:
`$python3 filesystem_server.py server.config` (Here, we have to change the path for the private key and public key in the config file.)

# TODOs

- Add Python API code for File System Manager to communicate with the uploader and downloader using the secure session key.
- Add Python API and example code for entity client in Python.
