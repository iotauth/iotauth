#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SST_ROOT/entity/c/examples/server_client_example/build"
./entity_client ../c_client.config "$@"
