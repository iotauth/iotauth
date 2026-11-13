# Integration Test Runners

This directory contains the shared helpers (`common.sh`) and two unified runners for IoTAuth client-server integration tests:

- `run_integration_test.sh` tests a client and a server that are both registered with Auth101, for the C, Node, and Python implementations.
- `run_multi_auth_test.sh` tests a client registered with Auth101 and a server registered with Auth102, for the Node, C, C++, and Python implementations.

Each test starts the Auth or Auths, runs the selected client and server, verifies the expected message exchange, and cleans up its processes.
Both runners are used by the GitHub Actions workflows described in [`.github/workflows/README.md`](../../.github/workflows/README.md).

## Single-Auth tests: `run_integration_test.sh`

### Usage

`run_integration_test.sh` provides one interface for selecting the client and server implementations:

```bash
./run_integration_test.sh --client python --server node
```

Both `--client` and `--server` accept `c`, `node`, or `python`.

The runner accepts the following options:

```text
--client <language>             Client implementation: c, node, or python
--server <language>             Server implementation: c, node, or python
--permanent-distribution-key    Use permanent distribution-key mode
--password <password>           Auth password used for setup and Auth101
--client-timeout <seconds>      Maximum time allowed for the client scenario
--service-timeout <seconds>     Maximum time to wait for services
--no-build                      Reuse existing build artifacts
--no-setup                      Reuse existing credentials and configuration
--no-verify                     Skip expected-output checks
--keep-logs                     Keep temporary logs after the test
--stop-existing                 Stop processes using the integration-test ports
--tmux                          Show Auth, server, and client in tmux panes
-h, --help                      Show command usage
```

`--permanent-distribution-key` currently works only with a Python client.

For example:

```bash
./run_integration_test.sh \
  --client python \
  --server python \
  --permanent-distribution-key
```

### Build and setup reuse

By default, the runner builds the required components and regenerates the integration-test configuration.

Use the following options to reuse artifacts from an earlier test in the same environment:

```bash
./run_integration_test.sh \
  --client python \
  --server node \
  --no-build \
  --no-setup
```

`--no-build` and `--no-setup` are intended for environments where an earlier test has already created the required artifacts.
Python environment preparation still runs when either the client or server is Python.

The integration tests use ports `21900`, `21901`, and `21100`.
Use `--stop-existing` when old test processes are still listening on those ports.

## Multi-Auth tests: `run_multi_auth_test.sh`

`run_multi_auth_test.sh` starts Auth101 and Auth102 (from `auth/properties/exampleAuth101.properties` and `exampleAuth102.properties`) and checks that `net1.client`, which is registered with Auth101, can communicate securely with `net2.server`, which is registered with Auth102:

```bash
./run_multi_auth_test.sh --entity node
```

`--entity` selects the implementation used for both the client and the server:

| `--entity` | What runs |
| --- | --- |
| `node` | `client.js` and `server.js` in `entity/node/example_entities` with the generated `configs/net1/client.config` and `configs/net2/server.config`. The runner drives their command prompts: `initComm net2.server`, `send` in both directions, and `finComm`. |
| `c` | `entity_client` and `entity_server` in `entity/c/examples/server_client_example`. The client connects twice, with two session keys. The C example server always listens on port 21100. |
| `cpp` | `entity_client` and `entity_server` in `entity/c/cpp/examples/server_client_example`. The client connects twice, with two session keys. The server listens on 22100, the port of `net2.server`. |
| `python` | `py_client.py` and `py_server.py` in `entity/python/examples`. The client sends three messages and receives a reply to each. The server listens on 22100. |

For `c`, `cpp`, and `python`, the runner writes `net1_client.config` and `net2_server.config` into its log directory, derived from the C example configs, with Auth102 and `net2.server` credentials for the server.

Besides the message exchange, the runner checks the Auth logs: the client's session key was issued by Auth101, so Auth102 must fetch it from Auth101 over the trusted-Auth channel.
Auth102 logs `Sending auth session key req to Auth 101`, and Auth101 logs `Received AuthSessionKeyReqMessage`.

The runner accepts the following options:

```text
--entity <implementation>       Client and server implementation: node, c, cpp, or python
--password <password>           Auth password used for setup and for both Auths
--client-timeout <seconds>      Maximum time allowed for each client step
--service-timeout <seconds>     Maximum time to wait for services
--no-build                      Skip the Maven build of Auth (the C and C++ examples are always built, incrementally)
--no-setup                      Reuse existing credentials and configuration
--keep-logs                     Keep temporary logs after the test
--stop-existing                 Stop processes using the multi-Auth test ports
-h, --help                      Show command usage
```

For example, to reuse the artifacts of an earlier test:

```bash
./run_multi_auth_test.sh --entity python --no-build --no-setup
```

Python environment preparation still runs for `--entity python`.

The multi-Auth tests use ports `21900`, `21901`, `22900`, `22901`, `21100` (C example server), and `22100` (`net2.server`).
Use `--stop-existing` when old test processes are still listening on those ports.

Logs are written to a temporary directory, which is kept when a test fails or `--keep-logs` is given.
