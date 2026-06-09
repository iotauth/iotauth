#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SST_ROOT/entity/c/examples/heterogeneous_client/build"
./heterogeneous_c_client ../../server_client_example/c_client.config "$@"
