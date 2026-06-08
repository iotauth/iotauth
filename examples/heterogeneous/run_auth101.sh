#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SST_ROOT/auth/auth-server"
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
