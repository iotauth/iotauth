#!/bin/bash

# Multi-Auth integration test.
#
# Starts two Auths (Auth101 and Auth102) and checks that an entity registered
# with Auth101 (net1.client) can establish a secure session with an entity
# registered with Auth102 (net2.server). The client gets its session key from
# Auth101; the server asks Auth102 for the same key, and Auth102 fetches it
# from Auth101 over the trusted-Auth channel. The test verifies the message
# exchange between the entities and that exchange between the two Auths.
#
# The client and the server use the same implementation, selected with
# --entity:
#   node  client.js and server.js in entity/node/example_entities, driven
#         through their command prompts (initComm net2.server, send, finComm)
#         with the generated configs/net1/client.config and
#         configs/net2/server.config.
#   c     entity_client and entity_server in
#         entity/c/examples/server_client_example.
#   cpp   entity_client and entity_server in
#         entity/c/cpp/examples/server_client_example.
# For c and cpp, net1.client and net2.server configs are written to the log
# directory, derived from the C example configs (c_client.config and
# c_server.config) with Auth102 and net2.server credentials for the server.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/common.sh"

ENTITY_IMPLEMENTATION=""

AUTH101_ENTITY_PORT=21900
AUTH101_TRUSTED_PORT=21901
AUTH102_ENTITY_PORT=22900
AUTH102_TRUSTED_PORT=22901
# Port of net2.server in the example graph; used by the Node and C++ servers.
NET2_SERVER_PORT=22100
# The C example server (entity_server.c) always listens on this port.
C_SERVER_PORT=21100
MULTI_AUTH_PORTS=(
	"$AUTH101_ENTITY_PORT" "$AUTH101_TRUSTED_PORT"
	"$AUTH102_ENTITY_PORT" "$AUTH102_TRUSTED_PORT"
	"$NET2_SERVER_PORT" "$C_SERVER_PORT"
)

NODE_EXAMPLES_DIR="$SST_ROOT/entity/node/example_entities"
C_EXAMPLE_DIR="$SST_ROOT/entity/c/examples/server_client_example"
CPP_EXAMPLE_DIR="$SST_ROOT/entity/c/cpp/examples/server_client_example"

NODE_CLIENT_MESSAGE_1="Hello net2.server from net1.client"
NODE_CLIENT_MESSAGE_2="Second message from net1.client"
NODE_SERVER_MESSAGE="Hello net1.client from net2.server"

AUTH101_PID=""
AUTH102_PID=""
LAUNCHED_PID=""
declare -a TAIL_PIDS=()

usage() {
	echo "Usage: $0 --entity <node|c|cpp> [options]"
	echo
	echo "Runs Auth101 and Auth102 and verifies that net1.client (registered with"
	echo "Auth101) can communicate securely with net2.server (registered with Auth102)."
	echo
	echo "Required:"
	echo "  --entity <implementation>   Client and server implementation: node, c, or cpp."
	echo
	echo "Options:"
	echo "  --password <password>       Auth password used for generation and the Auths."
	echo "  --client-timeout <seconds>  Maximum time for each client step. Default: 45."
	echo "  --service-timeout <seconds> Maximum time to wait for services. Default: 45."
	echo "  --no-build                  Skip the Maven build of Auth. The C and C++"
	echo "                              examples are always built (incrementally)."
	echo "  --no-setup                  Skip cleanAll.sh and generateAll.sh."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop processes using the multi-Auth test ports."
	echo "  -h, --help                  Show this help message."
	echo
	echo "Ports used: ${MULTI_AUTH_PORTS[*]}"
	echo
	echo "Examples:"
	echo "  $0 --entity node"
	echo "  $0 --entity c --no-build --no-setup"
	echo "  $0 --entity cpp --no-build --no-setup --stop-existing"
}

require_option_value() {
	local option="$1"
	local count="$2"
	if [[ "$count" -lt 2 ]]; then
		echo "Missing value for $option" >&2
		exit 1
	fi
}

parse_multi_auth_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--entity=*)
				ENTITY_IMPLEMENTATION="${1#*=}"
				;;
			--entity)
				require_option_value "$1" "$#"
				ENTITY_IMPLEMENTATION="$2"
				shift
				;;
			--password=*)
				AUTH_PASSWORD="${1#*=}"
				;;
			--password)
				require_option_value "$1" "$#"
				AUTH_PASSWORD="$2"
				shift
				;;
			--client-timeout=*)
				CLIENT_TIMEOUT="${1#*=}"
				;;
			--client-timeout)
				require_option_value "$1" "$#"
				CLIENT_TIMEOUT="$2"
				shift
				;;
			--service-timeout=*)
				SERVICE_TIMEOUT="${1#*=}"
				;;
			--service-timeout)
				require_option_value "$1" "$#"
				SERVICE_TIMEOUT="$2"
				shift
				;;
			--no-build)
				RUN_BUILD=false
				;;
			--no-setup)
				RUN_SETUP=false
				;;
			--keep-logs)
				KEEP_LOGS=true
				;;
			--stop-existing)
				STOP_EXISTING=true
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
}

validate_entity_implementation() {
	case "$ENTITY_IMPLEMENTATION" in
		node|c|cpp)
			;;
		"")
			echo "Missing required option: --entity" >&2
			usage >&2
			exit 1
			;;
		*)
			echo "Unsupported entity implementation: $ENTITY_IMPLEMENTATION" >&2
			echo "Expected one of: node, c, cpp" >&2
			exit 1
			;;
	esac
}

implementation_label() {
	case "$1" in
		node) echo "Node" ;;
		c) echo "C" ;;
		cpp) echo "C++" ;;
	esac
}

# --- Port helpers for the multi-Auth port set ---

multi_auth_port_pids() {
	local port
	for port in "${MULTI_AUTH_PORTS[@]}"; do
		port_pids "$port"
	done | awk 'NF && !seen[$0]++'
}

describe_multi_auth_port_users() {
	local port
	for port in "${MULTI_AUTH_PORTS[@]}"; do
		lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
	done
}

stop_existing_multi_auth_services() {
	local pids
	pids="$(multi_auth_port_pids)"
	if [[ -z "$pids" ]]; then
		return 0
	fi

	echo "[test] Stopping existing processes on ports ${MULTI_AUTH_PORTS[*]}:"
	describe_multi_auth_port_users
	# shellcheck disable=SC2086
	kill $pids 2>/dev/null || true
	sleep 2
	pids="$(multi_auth_port_pids)"
	if [[ -n "$pids" ]]; then
		# shellcheck disable=SC2086
		kill -9 $pids 2>/dev/null || true
		sleep 1
	fi
}

ensure_multi_auth_ports_available() {
	local pids
	pids="$(multi_auth_port_pids)"
	if [[ -z "$pids" ]]; then
		return 0
	fi

	echo "[test] Required ports are already in use." >&2
	describe_multi_auth_port_users >&2
	echo "[test] Stop those processes or rerun with --stop-existing." >&2
	exit 1
}

check_and_prepare_multi_auth_ports() {
	if [[ "$STOP_EXISTING" == true ]]; then
		stop_existing_multi_auth_services
	fi
	ensure_multi_auth_ports_available
}

# --- Build and setup ---

build_cpp_entities() {
	run_step cmake -S "$CPP_EXAMPLE_DIR" -B "$CPP_EXAMPLE_DIR/build"
	run_step cmake --build "$CPP_EXAMPLE_DIR/build"
}

prepare_test() {
	if [[ "$RUN_BUILD" == true ]]; then
		require_command mvn
		build_auth
	fi

	case "$ENTITY_IMPLEMENTATION" in
		node)
			require_command node
			require_command npm
			;;
		c)
			require_command cmake
			require_command make
			build_c_entities
			;;
		cpp)
			require_command cmake
			require_command make
			build_cpp_entities
			;;
	esac

	if [[ "$RUN_SETUP" == true ]]; then
		run_setup
	fi
}

# --- Logs and processes ---

setup_multi_auth_logs() {
	if [[ -z "$LOG_DIR" ]]; then
		LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sst-multi-auth-${ENTITY_IMPLEMENTATION}.XXXXXX")"
	else
		mkdir -p "$LOG_DIR"
	fi
	AUTH101_LOG="$LOG_DIR/auth101.log"
	AUTH102_LOG="$LOG_DIR/auth102.log"
	SERVER_LOG="$LOG_DIR/server.log"
	CLIENT_LOG="$LOG_DIR/client.log"
	trap cleanup EXIT INT TERM
	echo "[test] Logs: $LOG_DIR"
}

# Forwards the lines of a log file to the console with a [prefix].
start_log_tail() {
	local prefix="$1"
	local log_file="$2"
	# stderr is silenced so the subshell does not report the tail being stopped.
	(
		tail -n +1 -f "$log_file" 2>/dev/null | while IFS= read -r line; do
			echo "[$prefix] $line"
		done
	) 2>/dev/null &
	TAIL_PIDS+=($!)
}

# launch <label> <log_file> <stdin_path> <command...>
# Runs the command in the background with the given stdin, writes its output
# to the log file, forwards the log to the console, and sets LAUNCHED_PID.
launch() {
	local label="$1"
	local log_file="$2"
	local stdin_path="$3"
	shift 3
	: >"$log_file"
	(
		cd "$SST_ROOT"
		exec "$@"
	) <"$stdin_path" >"$log_file" 2>&1 &
	LAUNCHED_PID=$!
	start_log_tail "$label" "$log_file"
}

# Like wait_for_log, but fails as soon as the given process exits.
wait_for_log_from() {
	local pid="$1"
	local log_file="$2"
	local pattern="$3"
	local label="$4"
	local timeout="${5:-$SERVICE_TIMEOUT}"
	local elapsed=0

	while [[ "$elapsed" -lt "$timeout" ]]; do
		if grep -Fq "$pattern" "$log_file" 2>/dev/null; then
			echo "[test] $label."
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "[test] Process exited before: $label ($pattern)" >&2
			return 1
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	echo "[test] Timed out waiting for: $label ($pattern)" >&2
	return 1
}

# Waits for a process to exit within CLIENT_TIMEOUT and requires exit status 0.
wait_for_clean_exit() {
	local pid="$1"
	local label="$2"
	local elapsed=0
	local status=0

	while kill -0 "$pid" 2>/dev/null; do
		if [[ "$elapsed" -ge "$CLIENT_TIMEOUT" ]]; then
			echo "[test] $label timed out after ${CLIENT_TIMEOUT}s." >&2
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
			return 1
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	wait "$pid" 2>/dev/null || status=$?
	if [[ "$status" -ne 0 ]]; then
		echo "[test] $label exited with status $status." >&2
		return "$status"
	fi
	echo "[test] $label exited successfully."
}

cleanup() {
	local status=$?
	local pid
	# Close the command pipes of the Node entities.
	exec 3>&- 2>/dev/null || true
	exec 4>&- 2>/dev/null || true
	for pid in "$CLIENT_PID" "$SERVER_PID" "$AUTH102_PID" "$AUTH101_PID"; do
		if [[ -n "$pid" ]]; then
			pkill -P "$pid" 2>/dev/null || true
			kill "$pid" 2>/dev/null || true
		fi
	done
	for pid in "$CLIENT_PID" "$SERVER_PID" "$AUTH102_PID" "$AUTH101_PID"; do
		[[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
	done
	# Let the log tails print the last lines, then stop the tail processes;
	# their read loops end at end of input and the tail subshells exit normally.
	sleep 1
	for pid in "${TAIL_PIDS[@]+"${TAIL_PIDS[@]}"}"; do
		pkill -x -P "$pid" tail 2>/dev/null || true
	done
	for pid in "${TAIL_PIDS[@]+"${TAIL_PIDS[@]}"}"; do
		wait "$pid" 2>/dev/null || true
	done
	if [[ "$status" -ne 0 || "$KEEP_LOGS" == true ]]; then
		echo "[test] Logs kept in $LOG_DIR"
	else
		rm -rf "$LOG_DIR"
	fi
	exit "$status"
}

# --- Auths ---

start_auth_instance() {
	local auth_id="$1"
	local log_file="$2"
	echo "[test] Starting Auth$auth_id."
	launch "auth$auth_id" "$log_file" /dev/null bash -c \
		"cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && exec java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth${auth_id}.properties --password=$(quote_for_shell "$AUTH_PASSWORD")"
}

start_auths() {
	start_auth_instance 101 "$AUTH101_LOG"
	AUTH101_PID="$LAUNCHED_PID"
	start_auth_instance 102 "$AUTH102_LOG"
	AUTH102_PID="$LAUNCHED_PID"

	wait_for_log_from "$AUTH101_PID" "$AUTH101_LOG" "Enter command" "Auth101 is up"
	wait_for_log_from "$AUTH102_PID" "$AUTH102_LOG" "Enter command" "Auth102 is up"
	# "Enter command" can appear before the ports are bound; wait for the
	# entity ports and for the trusted-Auth port Auth102 will contact.
	wait_for_port "$AUTH101_ENTITY_PORT" "Auth101 entity service"
	wait_for_port "$AUTH101_TRUSTED_PORT" "Auth101 trusted-Auth service"
	wait_for_port "$AUTH102_ENTITY_PORT" "Auth102 entity service"
}

# --- Node scenario: client.js (net1.client) and server.js (net2.server) ---

# The Node entities read commands from stdin. Each gets a named pipe that this
# script keeps open read-write (fd 3 for the client, fd 4 for the server), so
# commands can be sent one at a time while the entity runs in the background.
send_node_client_command() {
	echo "[test] net1.client> $*"
	printf '%s\n' "$*" >&3
}

send_node_server_command() {
	echo "[test] net2.server> $*"
	printf '%s\n' "$*" >&4
}

run_node_scenario() {
	local server_in="$LOG_DIR/server.in"
	local client_in="$LOG_DIR/client.in"

	echo "[test] Starting Node server net2.server (Auth102) on port $NET2_SERVER_PORT."
	mkfifo "$server_in"
	exec 4<>"$server_in"
	launch server "$SERVER_LOG" "$server_in" bash -c \
		"cd $(quote_for_shell "$NODE_EXAMPLES_DIR") && exec node server.js configs/net2/server.config"
	SERVER_PID="$LAUNCHED_PID"
	wait_for_log_from "$SERVER_PID" "$SERVER_LOG" "Handler: listening on port $NET2_SERVER_PORT" "Node server net2.server is listening"

	echo "[test] Starting Node client net1.client (Auth101)."
	mkfifo "$client_in"
	exec 3<>"$client_in"
	launch client "$CLIENT_LOG" "$client_in" bash -c \
		"cd $(quote_for_shell "$NODE_EXAMPLES_DIR") && exec node client.js configs/net1/client.config"
	CLIENT_PID="$LAUNCHED_PID"

	send_node_client_command "initComm net2.server"
	wait_for_log_from "$CLIENT_PID" "$CLIENT_LOG" "Handler: communication initialization succeeded" \
		"net1.client established a secure connection to net2.server" "$CLIENT_TIMEOUT"

	send_node_client_command "send $NODE_CLIENT_MESSAGE_1"
	wait_for_log_from "$SERVER_PID" "$SERVER_LOG" "data: $NODE_CLIENT_MESSAGE_1" \
		"net2.server received the first message from net1.client" "$CLIENT_TIMEOUT"

	send_node_server_command "send $NODE_SERVER_MESSAGE"
	wait_for_log_from "$CLIENT_PID" "$CLIENT_LOG" "$NODE_SERVER_MESSAGE" \
		"net1.client received the message from net2.server" "$CLIENT_TIMEOUT"

	send_node_client_command "send $NODE_CLIENT_MESSAGE_2"
	wait_for_log_from "$SERVER_PID" "$SERVER_LOG" "data: $NODE_CLIENT_MESSAGE_2" \
		"net2.server received the second message from net1.client" "$CLIENT_TIMEOUT"

	send_node_client_command "finComm"
	wait_for_log_from "$CLIENT_PID" "$CLIENT_LOG" "Handler: secure connection with the server closed." \
		"net1.client closed the secure connection" "$CLIENT_TIMEOUT"
}

verify_node_output() {
	assert_log_contains "$CLIENT_LOG" "initComm command targeted to net2.server"
	assert_log_contains "$CLIENT_LOG" "Handler: communication initialization succeeded"
	assert_log_contains "$CLIENT_LOG" "Handler: data received from server via secure communication"
	assert_log_contains "$CLIENT_LOG" "$NODE_SERVER_MESSAGE"
	assert_log_contains "$SERVER_LOG" "Handler: socketID:"
	assert_log_contains "$SERVER_LOG" "data: $NODE_CLIENT_MESSAGE_1"
	assert_log_contains "$SERVER_LOG" "data: $NODE_CLIENT_MESSAGE_2"
}

# --- C and C++ scenarios: entity_client (net1.client), entity_server (net2.server) ---

# Both the C and the C++ example binaries read the C config format. The key
# paths are absolute because the examples resolve relative paths against the
# working directory.
write_net1_client_c_config() {
	local path="$1"
	local server_port="$2"
	cat >"$path" <<EOF
entityInfo.name=net1.client
entityInfo.purpose={"group":"Servers"}
entityInfo.number_key=3
authInfo.id=101
sessionKey.encryptionMode=AES_128_CBC
authInfo.pubkey.path=$SST_ROOT/entity/auth_certs/Auth101EntityCert.pem
entityInfo.privkey.path=$SST_ROOT/entity/credentials/keys/net1/Net1.ClientKey.pem
auth.ip.address=127.0.0.1
auth.port.number=$AUTH101_ENTITY_PORT
entity.server.ip.address=127.0.0.1
entity.server.port.number=$server_port
network.protocol=TCP
EOF
}

write_net2_server_c_config() {
	local path="$1"
	local server_port="$2"
	cat >"$path" <<EOF
entityInfo.name=net2.server
entityInfo.purpose={"keyId":00000000}
entityInfo.number_key=1
authInfo.id=102
sessionKey.encryptionMode=AES_128_CBC
authInfo.pubkey.path=$SST_ROOT/entity/auth_certs/Auth102EntityCert.pem
entityInfo.privkey.path=$SST_ROOT/entity/credentials/keys/net2/Net2.ServerKey.pem
auth.ip.address=127.0.0.1
auth.port.number=$AUTH102_ENTITY_PORT
entity.server.ip.address=127.0.0.1
entity.server.port.number=$server_port
network.protocol=TCP
EOF
}

# run_entity_server_client_scenario <label> <build_dir> <server_port>
# Runs entity_server (net2.server) and then entity_client (net1.client) from
# the build directory. The client connects twice and both programs exit on
# their own once the exchange is complete.
run_entity_server_client_scenario() {
	local label="$1"
	local build_dir="$2"
	local server_port="$3"
	local client_config="$LOG_DIR/net1_client.config"
	local server_config="$LOG_DIR/net2_server.config"

	write_net1_client_c_config "$client_config" "$server_port"
	write_net2_server_c_config "$server_config" "$server_port"

	echo "[test] Starting $label server net2.server (Auth102) on port $server_port."
	launch server "$SERVER_LOG" /dev/null bash -c \
		"cd $(quote_for_shell "$build_dir") && exec ./entity_server $(quote_for_shell "$server_config")"
	SERVER_PID="$LAUNCHED_PID"
	wait_for_port "$server_port" "$label server net2.server"

	echo "[test] Running $label client net1.client (Auth101)."
	launch client "$CLIENT_LOG" /dev/null bash -c \
		"cd $(quote_for_shell "$build_dir") && exec ./entity_client $(quote_for_shell "$client_config")"
	CLIENT_PID="$LAUNCHED_PID"

	wait_for_clean_exit "$CLIENT_PID" "$label client"
	CLIENT_PID=""
	wait_for_clean_exit "$SERVER_PID" "$label server"
	SERVER_PID=""
}

run_c_scenario() {
	run_entity_server_client_scenario "C" "$C_EXAMPLE_DIR/build" "$C_SERVER_PORT"
}

verify_c_output() {
	assert_log_no_errors "$SERVER_LOG" "C server"
	assert_log_no_errors "$CLIENT_LOG" "C client"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - second message"
	assert_log_contains "$SERVER_LOG" "Finished first communication"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2 - second message"
	assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client"
	assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client 2"
}

run_cpp_scenario() {
	run_entity_server_client_scenario "C++" "$CPP_EXAMPLE_DIR/build" "$NET2_SERVER_PORT"
}

verify_cpp_output() {
	assert_log_contains "$SERVER_LOG" "Entity server listening on port $NET2_SERVER_PORT"
	assert_log_contains "$SERVER_LOG" "Received: Hello server"
	assert_log_contains "$SERVER_LOG" "Received: Hello server - second message"
	assert_log_contains "$SERVER_LOG" "Finished first communication"
	assert_log_contains "$SERVER_LOG" "Received: Hello server 2"
	assert_log_contains "$SERVER_LOG" "Received: Hello server 2 - second message"
	assert_log_contains "$SERVER_LOG" "Finished second communication"
	assert_log_contains "$CLIENT_LOG" "Received: Hello client"
	assert_log_contains "$CLIENT_LOG" "Received: Hello client - second message"
	assert_log_contains "$CLIENT_LOG" "Received: Hello client 2"
	assert_log_contains "$CLIENT_LOG" "Received: Hello client 2 - second message"
}

# --- Cross-Auth verification ---

# net2.server presents a session key ID issued by Auth101, so Auth102 must
# request the key from Auth101 over the trusted-Auth channel.
verify_cross_auth_exchange() {
	echo "[test] Verifying that Auth102 obtained the session key from Auth101."
	assert_log_contains "$AUTH102_LOG" "This session key was generated by someone else"
	assert_log_contains "$AUTH102_LOG" "Sending auth session key req to Auth 101"
	assert_log_contains "$AUTH102_LOG" "Received AuthSessionKeyRespMessage"
	assert_log_contains "$AUTH101_LOG" "Received AuthSessionKeyReqMessage"
}

main() {
	parse_multi_auth_args "$@"
	validate_entity_implementation
	check_and_prepare_multi_auth_ports
	prepare_test

	setup_multi_auth_logs
	start_auths

	case "$ENTITY_IMPLEMENTATION" in
		node)
			run_node_scenario
			;;
		c)
			run_c_scenario
			;;
		cpp)
			run_cpp_scenario
			;;
	esac

	echo "[test] Verifying $(implementation_label "$ENTITY_IMPLEMENTATION") client and server output."
	case "$ENTITY_IMPLEMENTATION" in
		node) verify_node_output ;;
		c) verify_c_output ;;
		cpp) verify_cpp_output ;;
	esac
	verify_cross_auth_exchange

	echo "[test] Multi-Auth $(implementation_label "$ENTITY_IMPLEMENTATION") test passed: net1.client (Auth101) communicated with net2.server (Auth102)."
}

main "$@"
