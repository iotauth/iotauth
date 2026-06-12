#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

AUTH_PASSWORD="${AUTH_PASSWORD:-1234}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-45}"
SERVICE_TIMEOUT="${SERVICE_TIMEOUT:-45}"
RUN_SETUP=true
RUN_BUILD=true
VERIFY_OUTPUT=true
KEEP_LOGS=false
USE_TMUX=false
STOP_EXISTING=false
AUTH_PID=""
SERVER_PID=""
CLIENT_PID=""
AUTH_TAIL_PID=""
SERVER_TAIL_PID=""
LOG_DIR="${LOG_DIR:-}"

usage() {
	echo "Usage: $0 [options]"
	echo
	echo "Builds, prepares, runs, and verifies the Node-client-to-Node-server test."
	echo "Default password: 1234"
	echo
	echo "Options:"
	echo "  --password <password>       Auth password used for generation and Auth101."
	echo "  --client-timeout <seconds>  Max time for the Node client. Default: 45."
	echo "  --service-timeout <seconds> Max time to wait for services. Default: 45."
	echo "  --no-build                  Skip Maven build step."
	echo "  --no-setup                  Skip cleanAll.sh/generateAll.sh."
	echo "  --no-verify                 Run without checking Node server output."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop existing Auth/Node processes on the test ports."
	echo "  --tmux                      Show Auth, Node server, and Node client in tmux panes."
	echo "                              After the exchange completes, Auth and Node server are"
	echo "                              stopped while the tmux panes remain open for inspection."
	echo "  -h, --help                  Show this help message."
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--password=*)
			AUTH_PASSWORD="${1#*=}"
			;;
		--password)
			if [[ $# -lt 2 ]]; then
				echo "Missing value for --password" >&2
				exit 1
			fi
			AUTH_PASSWORD="$2"
			shift
			;;
		--client-timeout=*)
			CLIENT_TIMEOUT="${1#*=}"
			;;
		--client-timeout)
			if [[ $# -lt 2 ]]; then
				echo "Missing value for --client-timeout" >&2
				exit 1
			fi
			CLIENT_TIMEOUT="$2"
			shift
			;;
		--service-timeout=*)
			SERVICE_TIMEOUT="${1#*=}"
			;;
		--service-timeout)
			if [[ $# -lt 2 ]]; then
				echo "Missing value for --service-timeout" >&2
				exit 1
			fi
			SERVICE_TIMEOUT="$2"
			shift
			;;
		--no-build)
			RUN_BUILD=false
			;;
		--no-setup)
			RUN_SETUP=false
			;;
		--no-verify)
			VERIFY_OUTPUT=false
			;;
		--keep-logs)
			KEEP_LOGS=true
			;;
		--stop-existing)
			STOP_EXISTING=true
			;;
		--tmux)
			USE_TMUX=true
			VERIFY_OUTPUT=false
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 1
			;;
	esac
	shift
done

require_command() {
	local command_name="$1"
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "[test] Missing required command: $command_name" >&2
		echo "[test] Install the required Java, Node.js, and Maven dependencies, then retry." >&2
		exit 1
	fi
}

port_pids() {
	lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null || true
}

describe_port_users() {
	local port
	for port in 21900 21901 21100; do
		lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
	done
}

stop_existing_services() {
	local pids
	pids="$(printf "%s\n%s\n%s\n" "$(port_pids 21900)" "$(port_pids 21901)" "$(port_pids 21100)" | awk 'NF && !seen[$0]++')"
	if [[ -z "$pids" ]]; then
		return 0
	fi

	echo "[test] Stopping existing processes on ports 21900, 21901, or 21100:"
	describe_port_users
	# shellcheck disable=SC2086
	kill $pids 2>/dev/null || true
	sleep 2
	pids="$(printf "%s\n%s\n%s\n" "$(port_pids 21900)" "$(port_pids 21901)" "$(port_pids 21100)" | awk 'NF && !seen[$0]++')"
	if [[ -n "$pids" ]]; then
		# shellcheck disable=SC2086
		kill -9 $pids 2>/dev/null || true
		sleep 1
	fi
}

ensure_ports_available() {
	local pids
	pids="$(printf "%s\n%s\n%s\n" "$(port_pids 21900)" "$(port_pids 21901)" "$(port_pids 21100)" | awk 'NF && !seen[$0]++')"
	if [[ -z "$pids" ]]; then
		return 0
	fi

	echo "[test] Required ports are already in use." >&2
	describe_port_users >&2
	echo "[test] Stop those processes or rerun with --stop-existing." >&2
	exit 1
}

run_step() {
	echo "[test] $*"
	"$@"
}

quote_for_shell() {
	printf "%s" "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/"
}

prepare_test() {
	if [[ "$RUN_BUILD" == true ]]; then
		require_command mvn
		require_command node
		require_command npm

		run_step mvn -B package --file "$SST_ROOT/auth/pom.xml"
	fi

	if [[ "$RUN_SETUP" == true ]]; then
		require_command node
		require_command npm
		(
			cd "$SST_ROOT/examples"
			run_step ./cleanAll.sh
			run_step ./generateAll.sh -p "$AUTH_PASSWORD"
		)
	fi
}

if [[ "$USE_TMUX" == true ]]; then
	if ! command -v tmux >/dev/null 2>&1; then
		echo "tmux not found; falling back to same-terminal mode." >&2
		USE_TMUX=false
	fi
fi

if [[ "$STOP_EXISTING" == true ]]; then
	stop_existing_services
fi
ensure_ports_available

prepare_test

if [[ "$USE_TMUX" == true ]]; then
	SESSION_NAME="sst_node_client_node_server_test_$$"
	WAIT_SCRIPT="/tmp/${SESSION_NAME}_wait_and_stop.sh"
	PASSWORD_ARG="$(quote_for_shell "$AUTH_PASSWORD")"

	tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
	AUTH_PANE="$(tmux new-session -d -s "$SESSION_NAME" -P -F '#{pane_id}')"
	SERVER_PANE="$(tmux split-window -h -t "$AUTH_PANE" -P -F '#{pane_id}')"
	CLIENT_PANE="$(tmux split-window -v -t "$SERVER_PANE" -P -F '#{pane_id}')"
	AUTH_PANE_ARG="$(quote_for_shell "$AUTH_PANE")"
	SERVER_PANE_ARG="$(quote_for_shell "$SERVER_PANE")"

	tmux set-option -t "$SESSION_NAME" pane-border-status top
	tmux set-option -t "$SESSION_NAME" pane-border-format " #{pane_title} "
	tmux set-option -t "$SESSION_NAME" pane-border-style 'fg=white,bg=colour25'
	tmux set-option -t "$SESSION_NAME" pane-active-border-style 'fg=white,bg=colour25,bold'
	tmux set-option -t "$SESSION_NAME" status off
	tmux set-option -t "$SESSION_NAME" mouse on
	tmux set-window-option -t "$SESSION_NAME" remain-on-exit on

	tmux select-pane -t "$AUTH_PANE" -T "Auth101 — Ctrl+C to stop | Ctrl+B d to detach and kill"
	tmux select-pane -t "$SERVER_PANE" -T "Node server"
	tmux select-pane -t "$CLIENT_PANE" -T "Node client"

	cat >"$WAIT_SCRIPT" <<EOF
#!/bin/bash
set +e
sleep 6
cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") || exit 1
node autoClient.js configs/net1/client.config &
NODE_CLIENT_PID=\$!
elapsed=0
while [[ "\$elapsed" -lt $CLIENT_TIMEOUT ]] && kill -0 "\$NODE_CLIENT_PID" 2>/dev/null; do
	sleep 1
	elapsed=\$((elapsed + 1))
done
kill "\$NODE_CLIENT_PID" 2>/dev/null || true
wait "\$NODE_CLIENT_PID" 2>/dev/null || true
tmux send-keys -t $AUTH_PANE_ARG C-c
tmux send-keys -t $SERVER_PANE_ARG C-c
sleep 2
for port in 21900 21901 21100; do
	pids=\$(lsof -tiTCP:\$port -sTCP:LISTEN 2>/dev/null || true)
	if [[ -n "\$pids" ]]; then
		kill \$pids 2>/dev/null || true
	fi
done
echo
echo "[test] Node client finished. Auth and Node server were stopped; panes remain open for inspection."
EOF
	chmod +x "$WAIT_SCRIPT"

	tmux send-keys -t "$AUTH_PANE" "cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $PASSWORD_ARG" C-m
	tmux send-keys -t "$SERVER_PANE" "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") && node server.js configs/net1/server.config" C-m
	tmux send-keys -t "$CLIENT_PANE" "$WAIT_SCRIPT" C-m

	if [[ -t 0 ]]; then
		tmux attach-session -t "$SESSION_NAME"
	else
		echo "[test] tmux session $SESSION_NAME is running."
		echo "[test] Attach with: tmux attach-session -t $SESSION_NAME"
	fi
	exit 0
fi

if [[ -z "$LOG_DIR" ]]; then
	LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sst-node-client-node-server.XXXXXX")"
else
	mkdir -p "$LOG_DIR"
fi

AUTH_LOG="$LOG_DIR/auth.log"
SERVER_LOG="$LOG_DIR/server.log"
CLIENT_LOG="$LOG_DIR/client.log"

cleanup() {
	local status=$?
	if [[ -n "$CLIENT_PID" ]]; then
		kill "$CLIENT_PID" 2>/dev/null || true
	fi
	if [[ -n "$SERVER_TAIL_PID" ]]; then
		kill "$SERVER_TAIL_PID" 2>/dev/null || true
	fi
	if [[ -n "$AUTH_TAIL_PID" ]]; then
		kill "$AUTH_TAIL_PID" 2>/dev/null || true
	fi
	if [[ -n "$SERVER_PID" ]]; then
		kill "$SERVER_PID" 2>/dev/null || true
	fi
	if [[ -n "$AUTH_PID" ]]; then
		kill "$AUTH_PID" 2>/dev/null || true
	fi
	wait "$CLIENT_PID" 2>/dev/null || true
	wait "$SERVER_TAIL_PID" 2>/dev/null || true
	wait "$AUTH_TAIL_PID" 2>/dev/null || true
	wait "$SERVER_PID" 2>/dev/null || true
	wait "$AUTH_PID" 2>/dev/null || true
	if [[ "$status" -ne 0 || "$KEEP_LOGS" == true ]]; then
		echo "[test] Logs kept in $LOG_DIR"
	else
		rm -rf "$LOG_DIR"
	fi
	exit "$status"
}
trap cleanup EXIT INT TERM

start_service() {
	local prefix="$1"
	shift
	local log_file="$LOG_DIR/$prefix.log"

	(
		cd "$SST_ROOT"
		exec "$@" >"$log_file" 2>&1
	) &
	local service_pid=$!

	(
		tail -n +1 -f "$log_file" 2>/dev/null | sed -u "s/^/[$prefix] /"
	) &
	local tail_pid=$!

	case "$prefix" in
		auth)
			AUTH_PID="$service_pid"
			AUTH_TAIL_PID="$tail_pid"
			;;
		server)
			SERVER_PID="$service_pid"
			SERVER_TAIL_PID="$tail_pid"
			;;
	esac
}

wait_for_log() {
	local log_file="$1"
	local pattern="$2"
	local label="$3"
	local elapsed=0

	while [[ "$elapsed" -lt "$SERVICE_TIMEOUT" ]]; do
		if grep -Fq "$pattern" "$log_file" 2>/dev/null; then
			echo "[test] $label is ready."
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	echo "[test] Timed out waiting for $label: $pattern" >&2
	return 1
}

assert_log_contains() {
	local log_file="$1"
	local pattern="$2"

	if ! grep -Fq "$pattern" "$log_file"; then
		echo "[test] Missing expected output in $log_file:" >&2
		echo "[test]   $pattern" >&2
		return 1
	fi
}

echo "[test] Logs: $LOG_DIR"
echo "[test] Starting Auth101."
start_service auth bash -c \
	"cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && exec java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password=$(quote_for_shell "$AUTH_PASSWORD")"
wait_for_log "$AUTH_LOG" "Enter command" "Auth101"

echo "[test] Starting Node.js server."
start_service server bash -c \
	"cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") && exec node server.js configs/net1/server.config"
wait_for_log "$SERVER_LOG" "Handler: listening on port" "Node.js server"

echo "[test] Starting Node client."
(
	cd "$SST_ROOT/entity/node/example_entities"
	exec node autoClient.js configs/net1/client.config
) >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
(
	tail -n +1 -f "$CLIENT_LOG" 2>/dev/null | sed -u "s/^/[client] /"
) &

echo "[test] Waiting for Node server to receive both messages."
elapsed=0
while [[ "$elapsed" -lt "$CLIENT_TIMEOUT" ]]; do
	if grep -Fq "data: data1" "$SERVER_LOG" 2>/dev/null; then
		break
	fi
	sleep 1
	elapsed=$((elapsed + 1))
done

if ! grep -Fq "data: data1" "$SERVER_LOG" 2>/dev/null; then
	echo "[test] Timed out waiting for Node server to receive messages." >&2
	exit 1
fi

kill "$CLIENT_PID" 2>/dev/null || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

if [[ "$VERIFY_OUTPUT" == true ]]; then
	echo "[test] Checking Node.js server output."
	assert_log_contains "$SERVER_LOG" "Handler: socketID:"
	assert_log_contains "$SERVER_LOG" "data: data2"
	assert_log_contains "$SERVER_LOG" "data: data1"
fi

echo "[test] Node-client-to-Node-server test passed."
