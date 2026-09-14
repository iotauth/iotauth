#!/bin/bash

# ==============================================================================
# Full End-to-End Automated Test Script for IoTAuth C Entity & Auth Server
# Performs: Maven build -> Config & DB generation -> Auth Server launch ->
#          CMake build -> C Server/Client execution & verification
# ==============================================================================

set -e

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "======================================================================"
echo " Project Root: $PROJ_ROOT"
echo "======================================================================"

# Clean up processes on exit
cleanup() {
    echo ""
    echo "[Clean] Stopping background processes (C entity server & Auth Server)..."
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$AUTH_PID" ] && kill -0 "$AUTH_PID" 2>/dev/null; then
        kill -9 "$AUTH_PID" 2>/dev/null || true
    fi
    pkill -f auth-server-jar-with-dependencies 2>/dev/null || true
    pkill -f entity_server 2>/dev/null || true
}
trap cleanup EXIT

# Kill any existing auth-server or entity_server processes before start
pkill -f auth-server-jar-with-dependencies 2>/dev/null || true
pkill -f entity_server 2>/dev/null || true

PASSWORD="testpassword"
GRAPH_FILE="${1:-configs/default.graph}"

echo "Using graph file: $GRAPH_FILE"

# ------------------------------------------------------------------------------
# 1. Maven Clean & Package Java Auth Modules
# ------------------------------------------------------------------------------
echo ""
echo "[Step 1/5] Building Auth Java modules with Maven..."
cd "$PROJ_ROOT/auth"
mvn clean package -DskipTests

# ------------------------------------------------------------------------------
# 2. Clean & Generate Credentials, Configs, and Auth Databases
# ------------------------------------------------------------------------------
echo ""
echo "[Step 2/5] Cleaning and generating credentials & databases..."
cd "$PROJ_ROOT/examples"
./cleanAll.sh
./generateAll.sh \
  -g "$GRAPH_FILE" \
  -p "$PASSWORD" \
  -lc

# ------------------------------------------------------------------------------
# 3. Launch Auth Server 101 in Background
# ------------------------------------------------------------------------------
echo ""
echo "[Step 3/5] Starting Auth Server 101..."
cd "$PROJ_ROOT/auth/auth-server"
java -jar target/auth-server-jar-with-dependencies.jar \
  --properties ../properties/exampleAuth101.properties \
  -s "$PASSWORD" > auth_server.log 2>&1 &
AUTH_PID=$!
echo "Auth Server PID: $AUTH_PID. Waiting 3 seconds for initialization..."
sleep 3

if ! kill -0 "$AUTH_PID" 2>/dev/null; then
    echo "[Error] Auth Server failed to start! Log output:"
    cat auth_server.log
    exit 1
fi

# ------------------------------------------------------------------------------
# 4. Build C Entity Library & Server/Client Examples via CMake & Make
# ------------------------------------------------------------------------------
echo ""
echo "[Step 4/5] Compiling C entity API and examples with CMake..."
cd "$PROJ_ROOT/entity/c"
mkdir -p build && cd build
cmake .. && make

cd "$PROJ_ROOT/entity/c/examples/server_client_example"
mkdir -p build && cd build
cmake .. && make

# ------------------------------------------------------------------------------
# 5. Run C Entity Server & Client Communication Test
# ------------------------------------------------------------------------------
echo ""
echo "[Step 5/5] Testing C Entity Server & Client exchange..."
cd "$PROJ_ROOT/entity/c/examples/server_client_example/build"

./entity_server ../c_server.config > c_server.log 2>&1 &
SERVER_PID=$!
echo "C Entity Server PID: $SERVER_PID. Waiting 1 second..."
sleep 1

./entity_client ../c_client.config > c_client.log 2>&1
CLIENT_EXIT=$?

sleep 1

echo ""
echo "----------------------------------------------------------------------"
echo " C Client Log Output:"
echo "----------------------------------------------------------------------"
cat c_client.log

echo ""
echo "----------------------------------------------------------------------"
echo " C Server Log Output:"
echo "----------------------------------------------------------------------"
cat c_server.log

if [ $CLIENT_EXIT -eq 0 ] && grep -q "Received: Hello client" c_client.log; then
    echo ""
    echo "======================================================================"
    echo " SUCCESS: Full End-to-End C Entity & Auth Server test passed!"
    echo "======================================================================"
else
    echo ""
    echo "======================================================================"
    echo " FAILURE: C Entity communication test failed!"
    echo "======================================================================"
    exit 1
fi
