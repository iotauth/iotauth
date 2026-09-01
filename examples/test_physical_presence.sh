#!/bin/bash

# ==============================================================================
# Simple Test Script for Step 1: Robot -> Auth Server (Feasible Challenge Matcher)
# ==============================================================================

set -e

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "======================================================================"
echo " Project Root: $PROJ_ROOT"
echo "======================================================================"

# Clean up processes on exit
cleanup() {
    echo ""
    echo "[Clean] Stopping Auth Server and Locker..."
    if [ -n "$AUTH_PID" ] && kill -0 "$AUTH_PID" 2>/dev/null; then
        kill -9 "$AUTH_PID" 2>/dev/null || true
    fi
    if [ -n "$LOCKER_PID" ] && kill -0 "$LOCKER_PID" 2>/dev/null; then
        kill -9 "$LOCKER_PID" 2>/dev/null || true
    fi
    pkill -f auth-server-jar-with-dependencies 2>/dev/null || true
    pkill -f "build/locker" 2>/dev/null || true
    pkill -f robot 2>/dev/null || true
}
trap cleanup EXIT

# Kill any existing auth-server, locker, or robot processes before start
pkill -f auth-server-jar-with-dependencies 2>/dev/null || true
pkill -f "build/locker" 2>/dev/null || true
pkill -f robot 2>/dev/null || true

PASSWORD="testpassword"
GRAPH_FILE="configs/physical_presence.graph"
POLICY_FILE="policies/physical_presence.json"
CHALLENGES_FILE="physical_context_challenges/challenges.json"

# 1. Clean & Generate Auth Database with Physical Challenges
echo ""
echo "[1/4] Generating Auth DB with physical challenges..."
cd "$PROJ_ROOT/examples"
./cleanAll.sh
./generateAll.sh \
  -g "$GRAPH_FILE" \
  -po "$POLICY_FILE" \
  -ch "$CHALLENGES_FILE" \
  -p "$PASSWORD" \
  -lc

# 2. Launch Auth Server 101 in Background
echo ""
echo "[2/4] Starting Auth Server 101..."
cd "$PROJ_ROOT/auth/auth-server"
java -jar target/auth-server-jar-with-dependencies.jar \
  --properties ../properties/exampleAuth101.properties \
  -s "$PASSWORD" > auth_server.log 2>&1 &
AUTH_PID=$!
echo "Auth Server PID: $AUTH_PID. Waiting 3 seconds..."
sleep 3

if ! kill -0 "$AUTH_PID" 2>/dev/null; then
    echo "[Error] Auth Server failed to start! Log output:"
    cat auth_server.log
    exit 1
fi

# 3. Launch Locker Server in Background
echo ""
echo "[3/4] Starting Locker Server..."
cd "$PROJ_ROOT/entity/c/examples/physical_presence/build"
./locker ../locker.config > locker.log 2>&1 &
LOCKER_PID=$!
echo "Locker Server PID: $LOCKER_PID. Waiting 1 second..."
sleep 1

if ! kill -0 "$LOCKER_PID" 2>/dev/null; then
    echo "[Error] Locker Server failed to start! Log output:"
    cat locker.log
    exit 1
fi

# 4. Run Robot Client to Send Session Key Requests and Talk to Locker
echo ""
echo "[4/4] Running Robot Client..."
./robot ../robot.config > robot.log 2>&1 || true
sleep 1

echo ""
echo "======================================================================"
echo " Auth Server Log Output (Feasible Challenge Matcher):"
echo "======================================================================"
grep "FeasibleChallengeMatcher" "$PROJ_ROOT/auth/auth-server/auth_server.log" || cat "$PROJ_ROOT/auth/auth-server/auth_server.log"
echo "======================================================================"

echo ""
echo "======================================================================"
echo " Robot Client Log Output:"
echo "======================================================================"
cat "$PROJ_ROOT/entity/c/examples/physical_presence/build/robot.log"
echo "======================================================================"

echo ""
echo "======================================================================"
echo " Locker Server Log Output:"
echo "======================================================================"
cat "$PROJ_ROOT/entity/c/examples/physical_presence/build/locker.log"
echo "======================================================================"
