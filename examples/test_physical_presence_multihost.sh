#!/bin/bash

# ==============================================================================
# Multi-host physical presence test:
#   Auth   -> dongha@ada6000
#   Robot  -> pi42@pi42
#   Locker -> pi43@pi43
#
# Usage:
#   ./test_physical_presence_multihost.sh [--comm_type tcp|ultrasound] [--generate]
#
#   --comm_type   Transport for the Robot<->Locker handshake (default: tcp).
#                 Auth communication is always TCP regardless of this.
#   --generate    Regenerate the Auth DB on ada6000 (cleanAll.sh + generateAll.sh)
#                 and redistribute the freshly generated Auth cert + entity
#                 credentials to Robot/Locker. Skip this on repeat runs where
#                 the DB/credentials haven't changed -- it's the slow part.
#
# Assumes:
#   - Passwordless SSH to all three hosts.
#   - ~/project/iotauth checked out on the physical branch on all three hosts.
#   - robot/locker already built (with matching code) in
#     entity/c/examples/physical_presence/build/ on pi42/pi43. This script
#     does not rebuild them -- do that manually after code changes.
#   - Maven installed at /opt/apache-maven-3.9.8/bin on ada6000 (adjust
#     MVN_PATH below if that changes).
#
# SSH sessions to these hosts occasionally hang or drop a backgrounded
# process when the channel closes, so every remote call here is wrapped with
# a hard wall-clock timeout (macOS has no `timeout`, hence run_with_timeout
# below) and start_remote_and_verify() retries a few times before giving up.
# ==============================================================================

set -e

AUTH_HOST="dongha@ada6000"
ROBOT_HOST="pi42@pi42"
LOCKER_HOST="pi43@pi43"
REMOTE_REPO="project/iotauth"
PASSWORD="testpassword"
MVN_PATH="/opt/apache-maven-3.9.8/bin"
TAIL_PID=""

COMM_TYPE="tcp"
GENERATE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --comm_type) COMM_TYPE="$2"; shift 2 ;;
        --generate) GENERATE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Runs a command with a hard wall-clock timeout. Portable bash implementation
# since macOS has no `timeout`/`gtimeout` by default. Returns the wrapped
# command's exit status, or 124 if it had to be killed for running too long.
run_with_timeout() {
    local secs="$1"; shift
    "$@" &
    local cmd_pid=$!
    ( sleep "$secs" 2>/dev/null && kill -9 "$cmd_pid" 2>/dev/null ) &
    local watchdog_pid=$!
    local status=0
    wait "$cmd_pid" 2>/dev/null || status=$?
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    return $status
}

ssh_to() {
    local timeout_secs="$1" host="$2" cmd="$3"
    run_with_timeout "$timeout_secs" ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "$cmd"
}

scp_between() {
    local timeout_secs="$1" src="$2" dst="$3"
    run_with_timeout "$timeout_secs" scp -o BatchMode=yes -o ConnectTimeout=8 "$src" "$dst"
}

echo "======================================================================"
echo " Auth: $AUTH_HOST   Robot: $ROBOT_HOST   Locker: $LOCKER_HOST"
echo " comm_type=$COMM_TYPE  generate=$GENERATE"
echo "======================================================================"

# Always stop Auth (and Locker, which otherwise waits forever) on exit,
# whether the script succeeds, fails, or is interrupted.
cleanup() {
    echo ""
    echo "[Clean] Stopping Auth ($AUTH_HOST) and Locker ($LOCKER_HOST)..."
    [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
    ssh_to 15 "$AUTH_HOST" "pkill -f auth-server-jar-with-dependencies" 2>/dev/null || true
    ssh_to 15 "$LOCKER_HOST" "pkill -f './locker'" 2>/dev/null || true
    ssh_to 15 "$ROBOT_HOST" "pkill -f './robot'" 2>/dev/null || true
}
trap cleanup EXIT

# Starts a background process on a remote host and verifies (via pgrep) that
# it's still running a few seconds later, retrying a couple of times.
start_remote_and_verify() {
    local host="$1" start_cmd="$2" pgrep_pattern="$3" log_path="$4" label="$5"
    for attempt in 1 2 3; do
        ssh_to 15 "$host" "rm -f $log_path; $start_cmd" || true
        sleep 3
        if ssh_to 15 "$host" "pgrep -f '$pgrep_pattern' > /dev/null"; then
            return 0
        fi
        echo "[$label] did not survive on attempt $attempt/3, retrying..."
    done
    echo "[Error] $label failed to start after 3 attempts! Log output:"
    ssh_to 15 "$host" "cat $log_path" 2>/dev/null || true
    return 1
}

if [ "$GENERATE" = true ]; then
    echo ""
    echo "[1/5] Regenerating Auth DB on $AUTH_HOST..."
    ssh_to 120 "$AUTH_HOST" "export PATH=\$PATH:$MVN_PATH && cd $REMOTE_REPO/examples && ./cleanAll.sh && ./generateAll.sh -g configs/physical_presence_remote.graph -po policies/physical_presence.json -ch physical_context_challenges/challenges.json -p $PASSWORD -lc"

    echo ""
    echo "Distributing Auth cert + credentials to Robot and Locker..."
    ssh_to 15 "$ROBOT_HOST" "mkdir -p $REMOTE_REPO/entity/auth_certs $REMOTE_REPO/entity/credentials/certs/net1 $REMOTE_REPO/entity/credentials/keys/net1"
    ssh_to 15 "$LOCKER_HOST" "mkdir -p $REMOTE_REPO/entity/auth_certs $REMOTE_REPO/entity/credentials/certs/net1 $REMOTE_REPO/entity/credentials/keys/net1"

    scp_between 20 "$AUTH_HOST:$REMOTE_REPO/entity/auth_certs/Auth101EntityCert.pem" "$ROBOT_HOST:$REMOTE_REPO/entity/auth_certs/Auth101EntityCert.pem"
    scp_between 20 "$AUTH_HOST:$REMOTE_REPO/entity/credentials/certs/net1/Net1.Robot1Cert.pem" "$ROBOT_HOST:$REMOTE_REPO/entity/credentials/certs/net1/Net1.Robot1Cert.pem"
    scp_between 20 "$AUTH_HOST:$REMOTE_REPO/entity/credentials/keys/net1/Net1.Robot1Key.pem" "$ROBOT_HOST:$REMOTE_REPO/entity/credentials/keys/net1/Net1.Robot1Key.pem"

    scp_between 20 "$AUTH_HOST:$REMOTE_REPO/entity/auth_certs/Auth101EntityCert.pem" "$LOCKER_HOST:$REMOTE_REPO/entity/auth_certs/Auth101EntityCert.pem"
    scp_between 20 "$AUTH_HOST:$REMOTE_REPO/entity/credentials/certs/net1/Net1.Locker1Cert.pem" "$LOCKER_HOST:$REMOTE_REPO/entity/credentials/certs/net1/Net1.Locker1Cert.pem"
    scp_between 20 "$AUTH_HOST:$REMOTE_REPO/entity/credentials/keys/net1/Net1.Locker1Key.pem" "$LOCKER_HOST:$REMOTE_REPO/entity/credentials/keys/net1/Net1.Locker1Key.pem"
else
    echo ""
    echo "[1/5] Skipping DB regeneration (pass --generate to regenerate)."
fi

echo ""
echo "[2/5] Building and starting Auth server on $AUTH_HOST..."
ssh_to 60 "$AUTH_HOST" "export PATH=\$PATH:$MVN_PATH && cd $REMOTE_REPO/auth && mvn -q -DskipTests package"
ssh_to 15 "$AUTH_HOST" "pkill -f auth-server-jar-with-dependencies 2>/dev/null" || true
sleep 1
start_remote_and_verify "$AUTH_HOST" \
    "cd $REMOTE_REPO/auth/auth-server && setsid nohup java -jar target/auth-server-jar-with-dependencies.jar --properties ../properties/exampleAuth101.properties -s $PASSWORD > /tmp/auth_server_ada6000.log 2>&1 < /dev/null &" \
    "auth-server-jar-with-dependencies" "/tmp/auth_server_ada6000.log" "Auth Server" || exit 1

echo ""
echo "[3/5] Deploying per-Pi config files..."
scp_between 15 "$PROJ_ROOT/entity/c/examples/physical_presence/robot_pi42.config" "$ROBOT_HOST:$REMOTE_REPO/entity/c/examples/physical_presence/robot_pi42.config"
scp_between 15 "$PROJ_ROOT/entity/c/examples/physical_presence/locker_pi43.config" "$LOCKER_HOST:$REMOTE_REPO/entity/c/examples/physical_presence/locker_pi43.config"

echo ""
echo "[4/5] Starting Locker on $LOCKER_HOST (--comm_type $COMM_TYPE)..."
ssh_to 15 "$LOCKER_HOST" "pkill -f './locker' 2>/dev/null" || true
start_remote_and_verify "$LOCKER_HOST" \
    "cd $REMOTE_REPO/entity/c/examples/physical_presence/build && setsid nohup ./locker ../locker_pi43.config --comm_type $COMM_TYPE > /tmp/locker_test.log 2>&1 < /dev/null &" \
    "./locker" "/tmp/locker_test.log" "Locker" || exit 1

# Stream Locker's log live in this terminal, prefixed so it's distinguishable
# from Robot's own output below. Killed in cleanup() on exit.
ssh -o BatchMode=yes -o ConnectTimeout=8 "$LOCKER_HOST" "tail -n +1 -f /tmp/locker_test.log" 2>/dev/null | LC_ALL=C sed -u 's/^/[Locker] /' &
TAIL_PID=$!

echo ""
echo "[5/5] Running Robot on $ROBOT_HOST (--comm_type $COMM_TYPE)..."
# stdbuf forces line-buffered stdout over the ssh pipe (glibc otherwise fully
# buffers non-tty output, so Robot's log wouldn't show up until it exits).
ssh_to 100 "$ROBOT_HOST" "cd $REMOTE_REPO/entity/c/examples/physical_presence/build && stdbuf -oL -eL timeout 90 ./robot ../robot_pi42.config --comm_type $COMM_TYPE" 2>&1 | LC_ALL=C sed -u 's/^/[Robot] /' || true

sleep 2
echo ""
echo "======================================================================"
echo " Locker Log ($LOCKER_HOST):"
echo "======================================================================"
ssh_to 15 "$LOCKER_HOST" "cat /tmp/locker_test.log" || true
echo "======================================================================"
