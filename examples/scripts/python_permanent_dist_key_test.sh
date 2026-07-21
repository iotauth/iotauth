#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export PYTHON_CLIENT_CONFIG="../../node/example_entities/configs/net1/rcClient.config"
export EXPECT_PERMANENT_DIST_KEY=true

exec "$SCRIPT_DIR/python_client_python_server_test.sh" "$@"
