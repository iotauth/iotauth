# Integration Test Runner

This directory contains the shared helpers and unified runner for IoTAuth client-server integration tests with the C, Node, and Python implementations.
Each test starts Auth101, runs the selected client and server, verifies the expected message exchange, and cleans up its processes.

## Usage

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

## Build and setup reuse

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
