#!/bin/bash

# ==============================================================================
# Multi-host physical presence test:
#   Auth   -> pi41@pi41 (override with AUTH_HOST=user@host; the entity
#             configs' auth.ip.address must point at the same machine)
#   Robot  -> pi42@pi42
#   Locker -> pi43@pi43
#
# Usage:
#   ./test_physical_presence_multihost.sh [--comm_type tcp|ir|ultrasound|bluetooth]
#                                         [--generate]
#                                         [--ir-hk | --lifi-hk | --ultrasound-echo | --ble-rssi | --uwb]
#                                         [--echo-test-delay-ms N]
#
#   --comm_type   Transport for the Robot<->Locker handshake (default: tcp).
#                 Auth communication is always TCP regardless of this. "ir"
#                 runs Robot/Locker under sudo (pigpio needs direct GPIO
#                 access) -- see entity/c/ir_com/run_ir_test.sh for pigpio
#                 install steps; the build step below detects it the same
#                 way it detects ALSA for ultrasound.
#   --ir-hk       Require actual IR HK after any handshake transport. With
#                 --generate, select the IR-only CO_LOCATION catalog.
#   --lifi-hk     Require actual LiFi HK after any handshake transport. With
#                 --generate, select the LiFi-only CO_LOCATION catalog. The
#                 Pis are wired mirror-image: Robot (pi42) TX 23 / RX 22 (the
#                 defaults), Locker (pi43) TX 22 / RX 23; override with
#                 ROBOT_LIFI_ARGS / LOCKER_LIFI_ARGS.
#   --ultrasound-echo
#                 Require the mutual acoustic keyed echo for CO_LOCATION after a
#                 TCP handshake (--comm_type tcp only, for now). With --generate,
#                 select the ultrasound-only catalog. Succeeds only if, in this
#                 same run, both Robot and Locker logged their own echo PASS.
#                 Audio devices default to the USB mic/speaker card names
#                 (card numbers differ between the Pis); override with
#                 ROBOT_MIC/ROBOT_SPK/LOCKER_MIC/LOCKER_SPK env vars.
#   --ble-rssi    Require the mutual BLE RSSI proximity check for CO_LOCATION
#                 after a Bluetooth handshake (--comm_type bluetooth only).
#                 With --generate, select the BLE-only catalog. Succeeds only
#                 if, in this same run, both Robot and Locker logged their own
#                 RSSI PASS.
#   --uwb         Require the mutual UWB ranging check for CO_LOCATION after a
#                 TCP handshake (--comm_type tcp only), using the DWM3001CDK
#                 on each Pi (nRF52 USB port J20, CLI firmware). With
#                 --generate, select the UWB-only catalog. Succeeds only if,
#                 in this same run, both Robot and Locker logged their own
#                 ranging PASS.
#   --echo-test-delay-ms N
#                 Timing test only: Locker delays its acoustic answer by N ms,
#                 so Robot's measurement of Locker should fail past the limit.
#   --generate    Regenerate the Auth DB on the Auth host (cleanAll.sh + generateAll.sh)
#                 and redistribute the freshly generated Auth cert + entity
#                 credentials to Robot/Locker. Skip this on repeat runs where
#                 the DB/credentials haven't changed -- it's the slow part.
#
# Assumes:
#   - Passwordless SSH to all three hosts, and passwordless sudo on Robot and
#     Locker (only needed for --comm_type ir or bluetooth).
#   - ~/project/iotauth checked out on the physical branch on all three hosts,
#     with matching robot.c/locker.c code already pushed/pulled there. This
#     script (re)builds robot/locker on pi42/pi43 on every run.
#   - java, mvn, node/npm and openssl on the Auth host's PATH (set MVN_PATH
#     if mvn lives elsewhere, e.g. MVN_PATH=/opt/apache-maven-3.9.8/bin).
#   - The Auth host may be shared: if its Auth ports (21900/21901) are
#     already taken, this aborts instead of touching that process, and it
#     only ever stops the Auth server it started itself.
#
# SSH sessions to these hosts occasionally hang or drop a backgrounded
# process when the channel closes, so every remote call here is wrapped with
# a hard wall-clock timeout (macOS has no `timeout`, hence run_with_timeout
# below) and start_remote_and_verify() retries a few times before giving up.
# ==============================================================================

set -eo pipefail

AUTH_HOST="${AUTH_HOST:-pi41@pi41}"
ROBOT_HOST="pi42@pi42"
LOCKER_HOST="pi43@pi43"
REMOTE_REPO="project/iotauth"
PASSWORD="testpassword"
MVN_PATH="${MVN_PATH:-}"
MVN_ENV="${MVN_PATH:+export PATH=\$PATH:$MVN_PATH && }"
TAIL_PID=""

COMM_TYPE="tcp"
GENERATE=false
IR_HK=false
LIFI_HK=false
ECHO=false
ECHO_TEST_DELAY_MS=0
BLE=false
UWB=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --comm_type) COMM_TYPE="$2"; shift 2 ;;
        --ir-hk) IR_HK=true; shift ;;
        --lifi-hk) LIFI_HK=true; shift ;;
        --ultrasound-echo) ECHO=true; shift ;;
        --echo-test-delay-ms) ECHO_TEST_DELAY_MS="$2"; shift 2 ;;
        --ble-rssi) BLE=true; shift ;;
        --uwb) UWB=true; shift ;;
        --generate) GENERATE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done
CHECKS=0
for check in "$IR_HK" "$LIFI_HK" "$ECHO" "$BLE" "$UWB"; do
    [ "$check" = true ] && CHECKS=$((CHECKS + 1))
done
if [ "$CHECKS" -gt 1 ]; then
    echo "Choose at most one of --ir-hk, --lifi-hk, --ultrasound-echo, --ble-rssi, --uwb."
    exit 1
fi
if [ "$ECHO" = true ] && { [ "$IR_HK" = true ] || [ "$COMM_TYPE" != "tcp" ]; }; then
    echo "--ultrasound-echo runs after a TCP handshake only, and not with --ir-hk."
    exit 1
fi
if [ "$BLE" = true ] && { [ "$IR_HK" = true ] || [ "$ECHO" = true ] || [ "$COMM_TYPE" != "bluetooth" ]; }; then
    echo "--ble-rssi runs after a Bluetooth handshake only (--comm_type bluetooth), alone."
    exit 1
fi
if [ "$UWB" = true ] && { [ "$IR_HK" = true ] || [ "$ECHO" = true ] || [ "$BLE" = true ] || [ "$COMM_TYPE" != "tcp" ]; }; then
    echo "--uwb runs after a TCP handshake only, alone."
    exit 1
fi

# Same USB mic/speaker on both Pis, but under different ALSA card numbers,
# so address the cards by name.
ROBOT_MIC="${ROBOT_MIC:-plughw:CARD=MICROPHONE,DEV=0}"
ROBOT_SPK="${ROBOT_SPK:-plughw:CARD=Device,DEV=0}"
LOCKER_MIC="${LOCKER_MIC:-plughw:CARD=MICROPHONE,DEV=0}"
LOCKER_SPK="${LOCKER_SPK:-plughw:CARD=Device,DEV=0}"
# Unique per run, so an earlier run's log (or one left root-owned by a sudo
# run) can never be mistaken for this run's.
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
LOCKER_LOG="/tmp/locker_test.$RUN_ID.log"
AUTH_LOG="/tmp/auth_server.$RUN_ID.log"
AUTH_PID_FILE="/tmp/auth_server.$RUN_ID.pid"
ROBOT_LOCAL_LOG="$(mktemp -t robot_test.XXXXXX)"

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# pigpio (needed for --comm_type ir) requires direct GPIO access, and
# Bluetooth advertising/raw HCI commands need CAP_NET_ADMIN, so Robot and
# Locker run as root for IR or Bluetooth.
SUDO_PREFIX=""
ROBOT_TIMEOUT=90
HK_ARGS=""
CHALLENGE_CATALOG="physical_context_challenges/challenges.json"
if [ "$IR_HK" = true ]; then
    HK_ARGS="--require-ir-hk"
    CHALLENGE_CATALOG="physical_context_challenges/challenges_ir.json"
fi
if [ "$COMM_TYPE" = "ir" ] || [ "$IR_HK" = true ]; then
    SUDO_PREFIX="sudo "
    # IR's 50ms-per-bit rate makes even one ~72-100 byte handshake message
    # take on the order of 30s to transmit; three of them (hs1/hs2/hs3) plus
    # retries need much more headroom than ultrasound/tcp do.
    ROBOT_TIMEOUT=450
fi
if [ "$LIFI_HK" = true ]; then
    HK_ARGS="--require-lifi-hk"
    CHALLENGE_CATALOG="physical_context_challenges/challenges_lifi.json"
fi
if [ "$COMM_TYPE" = "lifi" ] || [ "$LIFI_HK" = true ]; then
    # pigpio, as for IR; the LiFi byte framing is slow too.
    SUDO_PREFIX="sudo "
    ROBOT_TIMEOUT=450
fi
if [ "$COMM_TYPE" = "bluetooth" ]; then
    SUDO_PREFIX="sudo "
fi
ROBOT_EXTRA_ARGS=""
LOCKER_EXTRA_ARGS=""
if [ "$COMM_TYPE" = "lifi" ] || [ "$LIFI_HK" = true ]; then
    ROBOT_EXTRA_ARGS="${ROBOT_LIFI_ARGS:-}"
    LOCKER_EXTRA_ARGS="${LOCKER_LIFI_ARGS:---lifi-tx-gpio 22 --lifi-rx-gpio 23}"
fi
if [ "$ECHO" = true ]; then
    HK_ARGS="--require-ultrasound-echo"
    CHALLENGE_CATALOG="physical_context_challenges/challenges_ultrasound.json"
    ROBOT_TIMEOUT=120
    ROBOT_EXTRA_ARGS="--mic $ROBOT_MIC --spk $ROBOT_SPK"
    LOCKER_EXTRA_ARGS="--mic $LOCKER_MIC --spk $LOCKER_SPK"
    if [ "$ECHO_TEST_DELAY_MS" != 0 ]; then
        LOCKER_EXTRA_ARGS="$LOCKER_EXTRA_ARGS --ultrasound-echo-test-delay-ms $ECHO_TEST_DELAY_MS"
    fi
fi
if [ "$UWB" = true ]; then
    HK_ARGS="--require-uwb"
    CHALLENGE_CATALOG="physical_context_challenges/challenges_uwb.json"
fi
if [ "$BLE" = true ]; then
    HK_ARGS="--require-ble-rssi"
    CHALLENGE_CATALOG="physical_context_challenges/challenges_ble.json"
fi

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
echo " comm_type=$COMM_TYPE  generate=$GENERATE  ir_hk=$IR_HK  lifi_hk=$LIFI_HK  ultrasound_echo=$ECHO  ble_rssi=$BLE  uwb=$UWB"
if [ "$ECHO" = true ]; then
    echo " catalog=$CHALLENGE_CATALOG  echo_test_delay_ms=$ECHO_TEST_DELAY_MS"
    echo " robot mic=$ROBOT_MIC spk=$ROBOT_SPK | locker mic=$LOCKER_MIC spk=$LOCKER_SPK"
fi
if [ "$BLE" = true ] || [ "$UWB" = true ]; then
    echo " catalog=$CHALLENGE_CATALOG"
fi
echo " run_id=$RUN_ID  locker_log=$LOCKER_LOG"
echo "======================================================================"

# Always stop Auth (and Locker, which otherwise waits forever) on exit,
# whether the script succeeds, fails, or is interrupted.
cleanup() {
    echo ""
    echo "[Clean] Stopping Auth ($AUTH_HOST) and Locker ($LOCKER_HOST)..."
    [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
    # Only the Auth server this run started (by PID), never anyone else's.
    ssh_to 15 "$AUTH_HOST" "[ -f $AUTH_PID_FILE ] && kill \$(cat $AUTH_PID_FILE); rm -f $AUTH_PID_FILE" 2>/dev/null || true
    # sudo pkill so this also cleans up a --comm_type ir run (started under
    # sudo for pigpio's direct GPIO access); harmless for tcp/ultrasound runs.
    ssh_to 15 "$LOCKER_HOST" "sudo pkill -f '[.]/locker'" 2>/dev/null || true
    ssh_to 15 "$ROBOT_HOST" "sudo pkill -f '[.]/robot'" 2>/dev/null || true
}
trap cleanup EXIT
# Explicit INT/TERM traps (not just EXIT) so this fires even when the shell
# would otherwise ignore SIGINT -- e.g. if this script itself is launched
# backgrounded (`... &`), bash disables SIGINT for it by default.
trap 'exit 130' INT TERM

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

# Checked before --generate wipes the DB and before starting Auth: if some
# Auth already listens there (e.g. another user's), stop rather than kill it
# or silently test against it (whose DB wouldn't know these credentials).
AUTH_PORTS_RE=':(21900|21901)( |$)'
if ssh_to 15 "$AUTH_HOST" "ss -ltn | grep -qE '$AUTH_PORTS_RE'"; then
    echo "[Error] Auth ports 21900/21901 are already in use on $AUTH_HOST:"
    ssh_to 15 "$AUTH_HOST" "ss -ltnp 2>/dev/null | grep -E '$AUTH_PORTS_RE'; ps -eo user,pid,lstart,args | grep '[a]uth-server-jar'" || true
    echo "Leaving it alone. Free the ports or set AUTH_HOST to another machine."
    exit 1
fi

if [ "$GENERATE" = true ]; then
    echo ""
    echo "[1/6] Regenerating Auth DB on $AUTH_HOST..."
    ssh_to 600 "$AUTH_HOST" "${MVN_ENV}cd $REMOTE_REPO/examples && ./cleanAll.sh && ./generateAll.sh -g configs/physical_presence_remote.graph -po policies/physical_presence.json -ch $CHALLENGE_CATALOG -p $PASSWORD -lc"

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
    echo "[1/6] Skipping DB regeneration (pass --generate to regenerate)."
fi

echo ""
echo "[2/6] Building and starting Auth server on $AUTH_HOST..."
ssh_to 300 "$AUTH_HOST" "${MVN_ENV}cd $REMOTE_REPO/auth && mvn -q -DskipTests package"
# stdin must never hit EOF: AuthCommandLine's interactive command loop reads
# from stdin and shuts the whole Auth server down on EOF (readLine()==null).
# /dev/zero blocks it in readLine() forever instead (/dev/null used to cause
# an immediate shutdown-on-start race). The PID is recorded so cleanup stops
# exactly this server; "started" means *it* is alive and the port is open,
# not merely that some auth-server process exists on the host.
ssh_to 15 "$AUTH_HOST" "cd $REMOTE_REPO/auth/auth-server && setsid nohup sh -c 'echo \$\$ > $AUTH_PID_FILE; exec java -jar target/auth-server-jar-with-dependencies.jar --properties ../properties/exampleAuth101.properties -s $PASSWORD' > $AUTH_LOG 2>&1 < /dev/zero &" || true
AUTH_UP=false
for _ in $(seq 1 30); do
    sleep 2
    if ssh_to 15 "$AUTH_HOST" "kill -0 \$(cat $AUTH_PID_FILE) 2>/dev/null && ss -ltn | grep -qE ':21900( |$)'"; then
        AUTH_UP=true
        break
    fi
done
if [ "$AUTH_UP" != true ]; then
    echo "[Error] Auth Server did not come up on $AUTH_HOST. Log output:"
    ssh_to 15 "$AUTH_HOST" "cat $AUTH_LOG" 2>/dev/null || true
    exit 1
fi

echo ""
echo "[3/6] Deploying per-Pi config files..."
scp_between 15 "$PROJ_ROOT/entity/c/examples/physical_presence/robot_pi42.config" "$ROBOT_HOST:$REMOTE_REPO/entity/c/examples/physical_presence/robot_pi42.config"
scp_between 15 "$PROJ_ROOT/entity/c/examples/physical_presence/locker_pi43.config" "$LOCKER_HOST:$REMOTE_REPO/entity/c/examples/physical_presence/locker_pi43.config"

echo ""
echo "[4/6] Building Robot on $ROBOT_HOST and Locker on $LOCKER_HOST..."
# libasound2-dev is required to link the ultrasound (ggwave/ALSA) transport,
# and libbluetooth-dev the Bluetooth one;
# apt is a no-op if it's already installed. pigpio (for --comm_type ir) is
# NOT an apt package and isn't installed here -- see
# entity/c/ir_com/run_ir_test.sh for its manual install steps; CMake just
# detects it if already present, same as it does for ALSA. The build dir is
# wiped instead of reused so a stale CMakeCache.txt never masks
# find_library() results from a previous run (e.g. before libasound2-dev or
# pigpio was installed).
BUILD_CMD="sudo apt-get install -y libasound2-dev libbluetooth-dev && cd $REMOTE_REPO/entity/c/examples/physical_presence && rm -rf build && mkdir build && cd build && cmake .. && make -j"
ssh_to 120 "$ROBOT_HOST" "$BUILD_CMD"
ssh_to 120 "$LOCKER_HOST" "$BUILD_CMD"
# Record exactly which sources were built (the Pis' entity/c may carry
# uncommitted, scp-synced files).
VERSION_CMD="cd $REMOTE_REPO/entity/c && echo \"entity/c HEAD \$(git rev-parse --short HEAD) \$(git status --short | wc -l) changed\" && sha256sum physical_com/hk.c physical_com/plan_json.c physical_com/session_ctl.c ultrasonic_com/ultrasonic_echo.c ultrasonic_com/ultrasonic_echo_plan.c ultrasonic_com/ultrasonic_audio.c bluetooth_com/bt_link.c bluetooth_com/bt_rssi.c bluetooth_com/bt_sst_handshake.c uwb_com/uwb_range.c uwb_com/uwb_cli_dev.c examples/physical_presence/hk_check.h | cut -c1-16,65-"
for host in "$ROBOT_HOST" "$LOCKER_HOST"; do
    echo "--- sources on $host ---"
    ssh_to 15 "$host" "$VERSION_CMD" || true
done

if [ "$COMM_TYPE" = "bluetooth" ]; then
    # Bluetooth is soft-blocked by default on these Pis. Robot connects to
    # Locker by its public LE address, read from Locker itself.
    BT_UP_CMD="for r in /sys/class/rfkill/rfkill*; do if [ \"\$(cat \$r/type)\" = bluetooth ]; then echo 0 | sudo tee \$r/soft > /dev/null; fi; done; bluetoothctl power on > /dev/null"
    ssh_to 20 "$ROBOT_HOST" "$BT_UP_CMD"
    ssh_to 20 "$LOCKER_HOST" "$BT_UP_CMD"
    LOCKER_BT_ADDR=$(ssh_to 15 "$LOCKER_HOST" "hciconfig hci0 | awk '/BD Address/ {print \$3}'")
    echo "Locker Bluetooth address: $LOCKER_BT_ADDR"
    ROBOT_EXTRA_ARGS="$ROBOT_EXTRA_ARGS --bt-peer $LOCKER_BT_ADDR"
fi

echo ""
echo "[5/6] Starting Locker on $LOCKER_HOST (--comm_type $COMM_TYPE)..."
ssh_to 15 "$LOCKER_HOST" "pkill -f './locker' 2>/dev/null" || true
# sudo first: sudo drops stdbuf's LD_PRELOAD, so stdbuf must run under it.
start_remote_and_verify "$LOCKER_HOST" \
    "cd $REMOTE_REPO/entity/c/examples/physical_presence/build && setsid nohup ${SUDO_PREFIX}stdbuf -oL -eL ./locker ../locker_pi43.config --comm_type $COMM_TYPE $HK_ARGS $LOCKER_EXTRA_ARGS > $LOCKER_LOG 2>&1 < /dev/null &" \
    "./locker" "$LOCKER_LOG" "Locker" || exit 1

# Stream Locker's log live in this terminal, prefixed so it's distinguishable
# from Robot's own output below. Killed in cleanup() on exit.
ssh -o BatchMode=yes -o ConnectTimeout=8 "$LOCKER_HOST" "tail -n +1 -f $LOCKER_LOG" 2>/dev/null | LC_ALL=C sed -u 's/^/[Locker] /' &
TAIL_PID=$!

echo ""
echo "[6/6] Running Robot on $ROBOT_HOST (--comm_type $COMM_TYPE)..."
# stdbuf forces line-buffered stdout over the ssh pipe (glibc otherwise fully
# buffers non-tty output, so Robot's log wouldn't show up until it exits).
ROBOT_STATUS=0
ssh_to $((ROBOT_TIMEOUT + 10)) "$ROBOT_HOST" "cd $REMOTE_REPO/entity/c/examples/physical_presence/build && stdbuf -oL -eL ${SUDO_PREFIX}timeout $ROBOT_TIMEOUT ./robot ../robot_pi42.config --comm_type $COMM_TYPE $HK_ARGS $ROBOT_EXTRA_ARGS" 2>&1 | tee "$ROBOT_LOCAL_LOG" | LC_ALL=C sed -u 's/^/[Robot] /' || ROBOT_STATUS=$?

# Let Locker finish (it exits after its own check and messaging), so its log
# is complete before it's judged.
for _ in $(seq 1 30); do
    ssh_to 10 "$LOCKER_HOST" "pgrep -f '[.]/locker' > /dev/null" || break
    sleep 1
done
LOCKER_LOCAL_LOG="$(mktemp -t locker_test.XXXXXX)"
ssh_to 15 "$LOCKER_HOST" "cat $LOCKER_LOG" > "$LOCKER_LOCAL_LOG" 2>/dev/null || true
echo ""
echo "======================================================================"
echo " Locker Log ($LOCKER_HOST:$LOCKER_LOG):"
echo "======================================================================"
cat "$LOCKER_LOCAL_LOG"
echo "======================================================================"

if [ "$ECHO" = true ]; then
    # Success means both endpoints measured their peer and passed in this
    # run -- not just Robot's exit status or a handshake message.
    ECHO_STATUS=0
    echo ""
    echo "Ultrasound echo results (this run):"
    for side in Robot Locker; do
        log="$ROBOT_LOCAL_LOG"; [ "$side" = Locker ] && log="$LOCKER_LOCAL_LOG"
        grep -h "ULTRASOUND ECHO: verified direction=" "$log" | sed "s/^/  [$side] /" || true
        grep -h "ULTRASOUND ECHO: local=" "$log" | sed "s/^/  [$side] /" || true
        if ! grep -q "ULTRASOUND ECHO: local=PASS .*result=PASS" "$log"; then
            echo "  [$side] did not report its own echo PASS in this run."
            ECHO_STATUS=1
        fi
    done
    if [ "$ROBOT_STATUS" = 0 ] && [ "$ECHO_STATUS" != 0 ]; then ROBOT_STATUS=1; fi
fi
if [ "$BLE" = true ]; then
    # Same rule as the echo: each endpoint's own RSSI check must pass.
    BLE_STATUS=0
    echo ""
    echo "BLE RSSI results (this run):"
    for side in Robot Locker; do
        log="$ROBOT_LOCAL_LOG"; [ "$side" = Locker ] && log="$LOCKER_LOCAL_LOG"
        grep -hE "BLE RSSI: (samples=|peer_median)" "$log" | sed "s/^/  [$side] /" || true
        if ! grep -q "BLE RSSI: samples=.*local=PASS" "$log" ||
           ! grep -q "BLE RSSI: peer_median.*result=PASS" "$log"; then
            echo "  [$side] did not report its own BLE RSSI PASS in this run."
            BLE_STATUS=1
        fi
    done
    if [ "$ROBOT_STATUS" = 0 ] && [ "$BLE_STATUS" != 0 ]; then ROBOT_STATUS=1; fi
fi
if [ "$IR_HK" = true ] || [ "$LIFI_HK" = true ]; then
    # Same rule: each endpoint's own HK tally must pass.
    M=IR; [ "$LIFI_HK" = true ] && M=LIFI
    HK_STATUS=0
    echo ""
    echo "$M HK results (this run):"
    for side in Robot Locker; do
        log="$ROBOT_LOCAL_LOG"; [ "$side" = Locker ] && log="$LOCKER_LOCAL_LOG"
        grep -h "$M HK: successes=" "$log" | sed "s/^/  [$side] /" || true
        if ! grep -q "$M HK: successes=.*local=PASS result=PASS" "$log"; then
            echo "  [$side] did not report its own $M HK PASS in this run."
            HK_STATUS=1
        fi
    done
    if [ "$ROBOT_STATUS" = 0 ] && [ "$HK_STATUS" != 0 ]; then ROBOT_STATUS=1; fi
fi
if [ "$UWB" = true ]; then
    # Same rule: each endpoint's own ranging must pass.
    UWB_STATUS=0
    echo ""
    echo "UWB ranging results (this run):"
    for side in Robot Locker; do
        log="$ROBOT_LOCAL_LOG"; [ "$side" = Locker ] && log="$LOCKER_LOCAL_LOG"
        grep -hE "UWB RANGE: (samples=|peer_median)" "$log" | sed "s/^/  [$side] /" || true
        if ! grep -q "UWB RANGE: samples=.*local=PASS" "$log" ||
           ! grep -q "UWB RANGE: peer_median.*result=PASS" "$log"; then
            echo "  [$side] did not report its own UWB ranging PASS in this run."
            UWB_STATUS=1
        fi
    done
    if [ "$ROBOT_STATUS" = 0 ] && [ "$UWB_STATUS" != 0 ]; then ROBOT_STATUS=1; fi
fi
rm -f "$ROBOT_LOCAL_LOG" "$LOCKER_LOCAL_LOG"

exit "$ROBOT_STATUS"
