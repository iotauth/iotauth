#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SST_ROOT/entity/node/example_entities"
node server.js configs/net1/server.config
