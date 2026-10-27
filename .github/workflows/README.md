# CI workflows

This directory holds the GitHub Actions workflows of the iotauth repository.
Unless noted otherwise, each workflow runs on every push to `main` and on every pull request targeting `main`.

| Workflow | File | What it runs |
| --- | --- | --- |
| Auth Server Build | [`maven.yml`](maven.yml) | Builds Auth with Maven on JDK 17 (`mvn -B package --file auth/pom.xml`). |
| Example Tests | [`example.yml`](example.yml) | Runs `examples/generateAll.sh` to generate the credentials, configuration files, and databases of the example Auths and entities. |
| Entity Integration Tests | [`integration-test.yml`](integration-test.yml) | Python unit tests, then end-to-end tests of every C, Node.js, and Python client-server combination against Auth101, plus the Python permanent distribution key scenario. See [Entity integration tests](#entity-integration-tests). |
| Multi-Auth Integration Tests | [`multi-auth-test.yml`](multi-auth-test.yml) | End-to-end tests with two Auths: a Node.js, C, C++, or Python client registered with Auth101 talks to a server of the same implementation registered with Auth102. Can also be started manually (`workflow_dispatch`). See [Multi-Auth integration tests](#multi-auth-integration-tests). |
| sst-c-api Tests | [`sst-c-api-tests.yml`](sst-c-api-tests.yml) | Calls the reusable `ci.yml` workflow of [iotauth/sst-c-api](https://github.com/iotauth/sst-c-api): C API unit tests (on sst-c-api `main`), and the C examples (server/client, file block encryption, IPFS file sharing) at the sst-c-api commit pinned by the `entity/c` submodule, against Auth. See [Cross-repository testing with sst-c-api](#cross-repository-testing-with-sst-c-api). |
| sst-c-api C++ Tests | [`sst-c-api-cpp-tests.yml`](sst-c-api-cpp-tests.yml) | Calls the reusable `ci-cpp.yml` workflow of sst-c-api: C++ API unit tests (on sst-c-api `main`), and the C++ examples (server/client, file block encryption, IPFS file sharing) at the sst-c-api commit pinned by the `entity/c` submodule, against Auth. See [Cross-repository testing with sst-c-api](#cross-repository-testing-with-sst-c-api). |
| Python Formatting | [`python-formatting.yml`](python-formatting.yml) | Ruff lint and format checks for `entity/python`. Runs on pull requests that change files under `entity/python/`. |
| CodeQL | [`codeql-analysis.yml`](codeql-analysis.yml) | CodeQL static analysis for Java, JavaScript, and Python. Also runs weekly on a schedule. |

## Entity integration tests

`integration-test.yml` has two jobs.

- `python-unit-tests` installs the Python package in `entity/python` and runs its unit tests with Python 3.12.
- `integration-test` runs the unified runner [`examples/scripts/run_integration_test.sh`](../../examples/scripts/run_integration_test.sh) ten times: the nine combinations of `--client` and `--server` among `c`, `node`, and `python`, and the Python client with `--permanent-distribution-key`.
  Each run builds (or reuses) Auth and the entities, generates (or reuses) the example credentials, starts Auth101, starts the server, runs the client, and checks the logs for the expected messages.

The first run (C client, C server) does the full build and credential setup.
If it succeeds, the later runs reuse those artifacts with `--no-build --no-setup`; if it fails, each later run does its own build and setup so the runs stay independent.
Every run has `continue-on-error`, so all ten always execute, and a final step fails the job if any run did not succeed.

The workflow also exposes `workflow_call` with an `sst-c-api-ref` input.
The sst-c-api repository uses it to run these integration tests against a specific sst-c-api commit instead of the submodule pin; see [Cross-repository testing with sst-c-api](#cross-repository-testing-with-sst-c-api).

## Multi-Auth integration tests

`multi-auth-test.yml` runs [`examples/scripts/run_multi_auth_test.sh`](../../examples/scripts/run_multi_auth_test.sh) once per entity implementation: `--entity node`, `c`, `cpp`, and `python`.
Each run:

1. Starts Auth101 and Auth102 from `auth/properties/exampleAuth101.properties` and `exampleAuth102.properties`, with the two-Auth topology of `examples/configs/default.graph`, in which Auth101 and Auth102 trust each other.
2. Starts a `net2.server` entity, which is registered with Auth102, and connects a `net1.client` entity, which is registered with Auth101, to it.
3. Checks the entity logs for the expected message exchange.
4. Checks the Auth logs: the client's session key was issued by Auth101, so Auth102 must fetch it from Auth101 over the trusted-Auth channel. Auth102 logs `Sending auth session key req to Auth 101`, and Auth101 logs `Received AuthSessionKeyReqMessage`.

The implementations differ in how the entities are driven:

| `--entity` | Client and server | Configuration |
| --- | --- | --- |
| `node` | `client.js` and `server.js` in `entity/node/example_entities`, driven through their command prompts (`initComm net2.server`, `send`, `finComm`), with messages in both directions. | The generated `configs/net1/client.config` and `configs/net2/server.config`. |
| `c` | `entity_client` and `entity_server` in `entity/c/examples/server_client_example`. The client connects twice, with two session keys. | Configs written by the runner, derived from the C example configs, with Auth102 and `net2.server` credentials for the server. The C example server always listens on port 21100. |
| `cpp` | `entity_client` and `entity_server` in `entity/c/cpp/examples/server_client_example`. The client connects twice, with two session keys. | The same generated configs; the server listens on 22100, the port of `net2.server`. |
| `python` | `py_client.py` and `py_server.py` in `entity/python/examples`. The client sends three messages and receives a reply to each. | The same generated configs; the server listens on 22100. |

As in the entity integration tests, the first run (Node) does the full Auth build and credential setup, the later runs reuse them when it succeeded, all runs always execute, and a final step fails the job if any run failed.

## Running the tests locally

Both runners live in [`examples/scripts/`](../../examples/scripts/) and are documented in [`examples/scripts/README.md`](../../examples/scripts/README.md).
For example:

```bash
cd examples/scripts
./run_integration_test.sh --client python --server node
./run_multi_auth_test.sh --entity cpp
```

Both runners build Auth and generate the example credentials by default; pass `--no-build --no-setup` to reuse existing artifacts.
The setup regenerates the example credentials with the runner's password (`1234` unless `--password` is given).

**Warning:** Without `--no-setup`, the runners delete any example credentials and configs you generated before, so back them up first.

## Cross-repository testing with sst-c-api

The C and C++ entity APIs live in the [iotauth/sst-c-api](https://github.com/iotauth/sst-c-api) repository, which is checked out here as the `entity/c` submodule.
The two repositories test each other:

- `sst-c-api-tests.yml` and `sst-c-api-cpp-tests.yml` in this repository call the reusable `ci.yml` and `ci-cpp.yml` workflows of sst-c-api with `iotauth-ref` set to the iotauth commit under test. The two jobs of each reusable workflow then use different sst-c-api versions:
  - The unit test job checks out sst-c-api `main`, so the C and C++ unit tests do not depend on the iotauth commit at all.
  - The integration test job checks out this repository at `iotauth-ref` with its submodules, so the sst-c-api examples run with the sst-c-api commit pinned by the `entity/c` submodule, against this version of Auth and of the example configuration. To test a newer sst-c-api commit here, update the submodule pin.
- The `ci.yml` workflow of sst-c-api calls `integration-test.yml` of this repository with `sst-c-api-ref` set to the sst-c-api commit under test, so the entity integration tests run with that C API instead of the submodule pin. When called this way, `integration-test.yml` checks out the `main` branch of this repository and the given sst-c-api ref into `entity/c`.

When `integration-test.yml` runs on a push or pull request in this repository, and in the multi-Auth tests always, the C and C++ entities come from the sst-c-api commit pinned by the submodule.

## Adding a CI test

- Put end-to-end test logic in a script under `examples/scripts/` that sources `common.sh` for the shared helpers (building, credential setup, starting and waiting for services, log assertions), so the test can be run locally in the same way as in CI.
- Add a workflow in this directory that runs the script, following `integration-test.yml` and `multi-auth-test.yml`: the first run does the build and setup, later runs reuse them, every run uses `continue-on-error`, and a final step fails the job if any run failed.
- Add the workflow to the table at the top of this file.
