#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SST_ROOT/entity/node/example_entities"
node heterogeneous_server.js configs/heterogeneous/nodeServer.config
