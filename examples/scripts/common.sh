# Common helper library for SST integration test scripts.
# Source this file from a test script; do not execute it directly.

# --- Variable defaults ---
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
declare -a ERROR_WATCHER_PIDS=()

# --- Port helpers ---

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

# --- Build helpers ---

require_command() {
	local command_name="$1"
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "[test] Missing required command: $command_name" >&2
		echo "[test] Install the required Java, Node.js, Maven, CMake, compiler, and OpenSSL dependencies, then retry." >&2
		exit 1
	fi
}

run_step() {
	echo "[test] $*"
	"$@"
}

build_auth() {
	run_step mvn -B -q package -DskipTests --file "$SST_ROOT/auth/pom.xml"
}

build_c_entities() {
	run_step cmake -S "$SST_ROOT/entity/c/examples/server_client_example" \
	              -B "$SST_ROOT/entity/c/examples/server_client_example/build"
	run_step cmake --build "$SST_ROOT/entity/c/examples/server_client_example/build"
}

run_setup() {
	require_command node
	require_command npm
	(
		cd "$SST_ROOT/examples"
		run_step ./cleanAll.sh
		run_step ./generateAll.sh -p "$AUTH_PASSWORD"
	)
}

# --- Service management ---

quote_for_shell() {
	printf "%s" "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/"
}

start_service() {
	local prefix="$1"
	shift
	local log_file="$LOG_DIR/$prefix.log"
	local main_pid="$$"

	(
		cd "$SST_ROOT"
		exec "$@" >"$log_file" 2>&1
	) &
	local service_pid=$!

	# Forward log lines to console; on the first ERROR: line, kill the service
	# and signal the test immediately so output stops after a single error line.
	(
		tail -n +1 -f "$log_file" 2>/dev/null | while IFS= read -r line; do
			echo "[$prefix] $line"
			if [[ "$line" == *"ERROR:"* ]]; then
				touch "$LOG_DIR/.error_detected"
				kill "$service_pid" 2>/dev/null || true
				kill -TERM "$main_pid" 2>/dev/null || true
				break
			fi
		done
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

wait_for_port() {
	local port="$1"
	local label="$2"
	local elapsed=0

	while [[ "$elapsed" -lt "$SERVICE_TIMEOUT" ]]; do
		if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
			echo "[test] $label is ready."
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	echo "[test] Timed out waiting for $label on port $port" >&2
	return 1
}

start_auth() {
	echo "[test] Starting Auth101."
	start_service auth bash -c \
		"cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && exec java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password=$(quote_for_shell "$AUTH_PASSWORD")"
	wait_for_log "$AUTH_LOG" "Enter command" "Auth101"
	# "Enter command" can appear before the entity TCP port (21900) is bound;
	# wait for the port explicitly so entities don't race during handshake.
	wait_for_port 21900 "Auth101 entity service"
}

# --- Client runner (C entity_client) ---

run_client_with_timeout() {
	(
		cd "$SST_ROOT/entity/c/examples/server_client_example/build"
		exec ./entity_client ../c_client.config
	) >"$CLIENT_LOG" 2>&1 &
	local client_pid=$!
	local elapsed=0

	while kill -0 "$client_pid" 2>/dev/null; do
		if [[ "$elapsed" -ge "$CLIENT_TIMEOUT" ]]; then
			echo "[test] C client timed out after ${CLIENT_TIMEOUT}s." >&2
			kill "$client_pid" 2>/dev/null || true
			wait "$client_pid" 2>/dev/null || true
			return 1
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	wait "$client_pid"
}

# --- Assertions ---

assert_log_contains() {
	local log_file="$1"
	local pattern="$2"

	if ! grep -Fq "$pattern" "$log_file"; then
		echo "[test] Missing expected output in $log_file:" >&2
		echo "[test]   $pattern" >&2
		return 1
	fi
}

assert_log_no_errors() {
	local log_file="$1"
	local label="$2"
	if grep -qF "ERROR:" "$log_file" 2>/dev/null; then
		echo "[test] Unexpected ERROR in $label log:" >&2
		grep -F "ERROR:" "$log_file" >&2
		return 1
	fi
}

# Background watcher: tails a log file and kills the test immediately if any
# line containing "ERROR:" is found.  Call after setup_logs for each C entity.
start_error_watcher() {
	local label="$1"
	local log_file="$2"
	local main_pid="$$"
	(
		while [[ ! -f "$log_file" ]]; do sleep 0.1; done
		tail -n +1 -f "$log_file" 2>/dev/null | while IFS= read -r line; do
			if [[ "$line" == *"ERROR:"* ]]; then
				echo "[test] Unexpected ERROR in $label log: $line" >&2
				touch "$LOG_DIR/.error_detected"
				kill -TERM "$main_pid" 2>/dev/null || true
				break
			fi
		done
	) &
	ERROR_WATCHER_PIDS+=($!)
}

# --- Lifecycle ---

cleanup() {
	local status=$?
	[[ -f "${LOG_DIR:-}/.error_detected" ]] && status=1
	local pid
	for pid in "${ERROR_WATCHER_PIDS[@]+"${ERROR_WATCHER_PIDS[@]}"}"; do
		kill "$pid" 2>/dev/null || true
	done
	for pid in "$CLIENT_PID" "$SERVER_TAIL_PID" "$AUTH_TAIL_PID" "$SERVER_PID" "$AUTH_PID"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	for pid in "$CLIENT_PID" "$SERVER_TAIL_PID" "$AUTH_TAIL_PID" "$SERVER_PID" "$AUTH_PID"; do
		[[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
	done
	if [[ "$status" -ne 0 || "$KEEP_LOGS" == true ]]; then
		echo "[test] Logs kept in $LOG_DIR"
	else
		rm -rf "$LOG_DIR"
	fi
	exit "$status"
}

setup_logs() {
	local prefix="$1"
	if [[ -z "$LOG_DIR" ]]; then
		LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sst-${prefix}.XXXXXX")"
	else
		mkdir -p "$LOG_DIR"
	fi
	AUTH_LOG="$LOG_DIR/auth.log"
	SERVER_LOG="$LOG_DIR/server.log"
	CLIENT_LOG="$LOG_DIR/client.log"
	trap cleanup EXIT INT TERM
	echo "[test] Logs: $LOG_DIR"
}

# --- Argument parsing ---

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--password=*)
				AUTH_PASSWORD="${1#*=}"
				;;
			--password)
				if [[ $# -lt 2 ]]; then echo "Missing value for --password" >&2; exit 1; fi
				AUTH_PASSWORD="$2"
				shift
				;;
			--client-timeout=*)
				CLIENT_TIMEOUT="${1#*=}"
				;;
			--client-timeout)
				if [[ $# -lt 2 ]]; then echo "Missing value for --client-timeout" >&2; exit 1; fi
				CLIENT_TIMEOUT="$2"
				shift
				;;
			--service-timeout=*)
				SERVICE_TIMEOUT="${1#*=}"
				;;
			--service-timeout)
				if [[ $# -lt 2 ]]; then echo "Missing value for --service-timeout" >&2; exit 1; fi
				SERVICE_TIMEOUT="$2"
				shift
				;;
			--no-build)    RUN_BUILD=false ;;
			--no-setup)    RUN_SETUP=false ;;
			--no-verify)   VERIFY_OUTPUT=false ;;
			--keep-logs)   KEEP_LOGS=true ;;
			--stop-existing) STOP_EXISTING=true ;;
			--tmux)        USE_TMUX=true; VERIFY_OUTPUT=false ;;
			-h|--help)     usage; exit 0 ;;
			*)
				echo "Unknown option: $1" >&2
				usage >&2
				exit 1
				;;
		esac
		shift
	done
}

check_and_prepare_ports() {
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
}

# --- tmux helpers ---

# Sets up a 3-pane tmux session (Auth | Server / Client) with standard styling.
# After calling this, AUTH_PANE, SERVER_PANE, CLIENT_PANE, AUTH_PANE_ARG, and
# SERVER_PANE_ARG are available as global variables.
setup_tmux_session() {
	local session_name="$1"
	local server_pane_label="$2"
	local client_pane_label="$3"

	tmux kill-session -t "$session_name" 2>/dev/null || true
	AUTH_PANE="$(tmux new-session -d -s "$session_name" -P -F '#{pane_id}')"
	SERVER_PANE="$(tmux split-window -h -t "$AUTH_PANE" -P -F '#{pane_id}')"
	CLIENT_PANE="$(tmux split-window -v -t "$SERVER_PANE" -P -F '#{pane_id}')"
	AUTH_PANE_ARG="$(quote_for_shell "$AUTH_PANE")"
	SERVER_PANE_ARG="$(quote_for_shell "$SERVER_PANE")"

	tmux set-option -t "$session_name" pane-border-status top
	tmux set-option -t "$session_name" pane-border-format " #{pane_title} "
	tmux set-option -t "$session_name" pane-border-style 'fg=white,bg=colour25'
	tmux set-option -t "$session_name" pane-active-border-style 'fg=white,bg=colour25,bold'
	tmux set-option -t "$session_name" status off
	tmux set-option -t "$session_name" mouse on
	tmux set-window-option -t "$session_name" remain-on-exit on

	tmux select-pane -t "$AUTH_PANE" -T "Auth101 — Ctrl+C to stop | Ctrl+B d to detach and kill"
	tmux select-pane -t "$SERVER_PANE" -T "$server_pane_label"
	tmux select-pane -t "$CLIENT_PANE" -T "$client_pane_label"
}

attach_tmux_session() {
	local session_name="$1"
	if [[ -t 0 ]]; then
		tmux attach-session -t "$session_name"
	else
		echo "[test] tmux session $session_name is running."
		echo "[test] Attach with: tmux attach-session -t $session_name"
	fi
}
