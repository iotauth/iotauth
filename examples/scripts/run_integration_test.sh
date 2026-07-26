#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/common.sh"

CLIENT_IMPLEMENTATION=""
SERVER_IMPLEMENTATION=""
PERMANENT_DISTRIBUTION_KEY=false
PYTHON_CLIENT_CONFIG=""
PYTHON_SERVER_CONFIG="$SST_ROOT/entity/node/example_entities/configs/net1/server.config"

usage() {
	echo "Usage: $0 --client <c|node|python> --server <c|node|python> [options]"
	echo
	echo "Builds, prepares, runs, and verifies one IoTAuth client-server integration test."
	echo
	echo "Required:"
	echo "  --client <language>         Client implementation: c, node, or python."
	echo "  --server <language>         Server implementation: c, node, or python."
	echo
	echo "Options:"
	echo "  --permanent-distribution-key"
	echo "                              Use the permanent distribution-key Python client."
	echo "  --password <password>       Auth password used for generation and Auth101."
	echo "  --client-timeout <seconds>  Maximum time for the client scenario. Default: 45."
	echo "  --service-timeout <seconds> Maximum time to wait for services. Default: 45."
	echo "  --no-build                  Skip Maven and entity build steps."
	echo "  --no-setup                  Skip cleanAll.sh and generateAll.sh."
	echo "  --no-verify                 Run without checking expected output."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop processes using the integration-test ports."
	echo "  --tmux                      Show Auth, server, and client in tmux panes."
	echo "  -h, --help                  Show this help message."
	echo
	echo "Examples:"
	echo "  $0 --client python --server node"
	echo "  $0 --client c --server python --no-build --no-setup"
	echo "  $0 --client python --server python --permanent-distribution-key"
}

require_option_value() {
	local option="$1"
	local count="$2"
	if [[ "$count" -lt 2 ]]; then
		echo "Missing value for $option" >&2
		exit 1
	fi
}

parse_runner_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--client=*)
				CLIENT_IMPLEMENTATION="${1#*=}"
				;;
			--client)
				require_option_value "$1" "$#"
				CLIENT_IMPLEMENTATION="$2"
				shift
				;;
			--server=*)
				SERVER_IMPLEMENTATION="${1#*=}"
				;;
			--server)
				require_option_value "$1" "$#"
				SERVER_IMPLEMENTATION="$2"
				shift
				;;
			--permanent-distribution-key)
				PERMANENT_DISTRIBUTION_KEY=true
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
}

validate_implementation() {
	local role="$1"
	local implementation="$2"
	case "$implementation" in
		c|node|python)
			;;
		"")
			echo "Missing required option: --$role" >&2
			usage >&2
			exit 1
			;;
		*)
			echo "Unsupported $role implementation: $implementation" >&2
			echo "Expected one of: c, node, python" >&2
			exit 1
			;;
	esac
}

validate_selection() {
	validate_implementation "client" "$CLIENT_IMPLEMENTATION"
	validate_implementation "server" "$SERVER_IMPLEMENTATION"
	if [[ "$PERMANENT_DISTRIBUTION_KEY" == true && "$CLIENT_IMPLEMENTATION" != "python" ]]; then
		echo "--permanent-distribution-key requires --client python" >&2
		exit 1
	fi
}

uses_implementation() {
	local implementation="$1"
	[[ "$CLIENT_IMPLEMENTATION" == "$implementation" || "$SERVER_IMPLEMENTATION" == "$implementation" ]]
}

implementation_label() {
	case "$1" in
		c) echo "C" ;;
		node) echo "Node" ;;
		python) echo "Python" ;;
	esac
}

prepare_test() {
	if [[ "$RUN_BUILD" == true ]]; then
		require_command mvn
		build_auth

		if uses_implementation c; then
			require_command cmake
			require_command make
			build_c_entities
		fi
		if uses_implementation node; then
			require_command node
			require_command npm
		fi
		if uses_implementation python; then
			require_command python3
		fi
	fi

	if [[ "$RUN_SETUP" == true ]]; then
		run_setup
	fi

	if uses_implementation python; then
		build_python_entities
	fi
}

select_python_config() {
	if [[ "$PERMANENT_DISTRIBUTION_KEY" == true ]]; then
		PYTHON_CLIENT_CONFIG="$SST_ROOT/entity/node/example_entities/configs/net1/rcClient.config"
	else
		PYTHON_CLIENT_CONFIG="$SST_ROOT/entity/node/example_entities/configs/net1/client.config"
	fi
}

validate_python_configs() {
	if [[ "$CLIENT_IMPLEMENTATION" == "python" ]]; then
		if [[ ! -f "$PYTHON_CLIENT_CONFIG" ]]; then
			echo "[test] Python client config does not exist: $PYTHON_CLIENT_CONFIG" >&2
			exit 1
		fi
		if [[ "$PERMANENT_DISTRIBUTION_KEY" == true ]]; then
			if ! grep -Eq '"usePermanentDistKey"[[:space:]]*:[[:space:]]*true' "$PYTHON_CLIENT_CONFIG"; then
				echo "[test] Expected a permanent distribution-key config: $PYTHON_CLIENT_CONFIG" >&2
				exit 1
			fi
			echo "[test] Verified permanent distribution-key client config."
		fi
	fi
	if [[ "$SERVER_IMPLEMENTATION" == "python" && ! -f "$PYTHON_SERVER_CONFIG" ]]; then
		echo "[test] Python server config does not exist: $PYTHON_SERVER_CONFIG" >&2
		exit 1
	fi
}

start_selected_server() {
	case "$SERVER_IMPLEMENTATION" in
		c)
			echo "[test] Starting C server."
			start_service server bash -c \
				"cd $(quote_for_shell "$SST_ROOT/entity/c/examples/server_client_example/build") && exec ./entity_server ../c_server.config"
			wait_for_port 21100 "C server"
			;;
		node)
			echo "[test] Starting Node server."
			start_service server bash -c \
				"cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") && exec node server.js configs/net1/server.config"
			wait_for_log "$SERVER_LOG" "Handler: listening on port" "Node server"
			;;
		python)
			echo "[test] Starting Python server."
			case "$CLIENT_IMPLEMENTATION" in
				c)
					start_service server bash -c \
						"cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u py_server.py -n 2 $(quote_for_shell "$PYTHON_SERVER_CONFIG"); sleep 0.5; done"
					;;
				node)
					start_service server bash -c \
						"cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u py_server.py $(quote_for_shell "$PYTHON_SERVER_CONFIG"); sleep 0.5; done"
					;;
				python)
					start_service server bash -c \
						"cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && exec python3 -u py_server.py $(quote_for_shell "$PYTHON_SERVER_CONFIG")"
					;;
			esac
			wait_for_port 21100 "Python server"
			;;
	esac
}

start_client_log_tail() {
	(
		tail -n +1 -f "$CLIENT_LOG" 2>/dev/null | sed -u "s/^/[client] /"
	) &
	TAIL_PID=$!
}

wait_for_process_exit() {
	local pid="$1"
	local label="$2"
	local elapsed=0
	while kill -0 "$pid" 2>/dev/null; do
		if [[ "$elapsed" -ge "$CLIENT_TIMEOUT" ]]; then
			echo "[test] $label timed out after ${CLIENT_TIMEOUT}s." >&2
			kill "$pid" 2>/dev/null || true
			return 1
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done
}

reap_successful_process() {
	local pid="$1"
	local label="$2"
	local status=0
	wait "$pid" 2>/dev/null || status=$?
	if [[ "$status" -ne 0 ]]; then
		echo "[test] $label exited with status $status." >&2
		return "$status"
	fi
}

wait_for_c_server_completion() {
	local pid="$SERVER_PID"
	echo "[test] Waiting for C server to complete both connections."
	wait_for_process_exit "$pid" "C server"
	reap_successful_process "$pid" "C server"
	SERVER_PID=""
}

stop_background_client() {
	if [[ -n "$CLIENT_PID" ]]; then
		kill "$CLIENT_PID" 2>/dev/null || true
		wait "$CLIENT_PID" 2>/dev/null || true
		CLIENT_PID=""
	fi
}

run_c_client() {
	echo "[test] Running C client."
	run_client_with_timeout
	if [[ "$SERVER_IMPLEMENTATION" == "c" ]]; then
		wait_for_log "$SERVER_LOG" "LOG: Received: Hello server 2 - second message" "C server" 15
	fi
}

run_node_client() {
	echo "[test] Starting Node client."
	(
		cd "$SST_ROOT/entity/node/example_entities"
		exec node autoClient.js configs/net1/client.config
	) >"$CLIENT_LOG" 2>&1 &
	CLIENT_PID=$!
	start_client_log_tail

	case "$SERVER_IMPLEMENTATION" in
		c)
			wait_for_c_server_completion
			;;
		node)
			echo "[test] Waiting for Node server to receive both messages."
			wait_for_log "$SERVER_LOG" "data: data1" "Node server message exchange" "$CLIENT_TIMEOUT"
			;;
		python)
			echo "[test] Waiting for Python server to receive both messages."
			wait_for_log "$SERVER_LOG" "LOG: Received: data1" "Python server message exchange" "$CLIENT_TIMEOUT"
			;;
	esac

	stop_background_client
}

run_python_client() {
	if [[ "$SERVER_IMPLEMENTATION" == "c" ]]; then
		echo "[test] Starting Python client twice to satisfy the C server."
		(
			cd "$SST_ROOT/entity/python/examples"
			source ../.venv/bin/activate
			python3 py_client.py "$PYTHON_CLIENT_CONFIG"
			sleep 2
			exec python3 py_client.py "$PYTHON_CLIENT_CONFIG"
		) >"$CLIENT_LOG" 2>&1 &
		CLIENT_PID=$!
		start_client_log_tail
		wait_for_c_server_completion
		stop_background_client
		return
	fi

	echo "[test] Running Python client."
	(
		cd "$SST_ROOT/entity/python/examples"
		source ../.venv/bin/activate
		exec python3 py_client.py "$PYTHON_CLIENT_CONFIG"
	) >"$CLIENT_LOG" 2>&1 &
	CLIENT_PID=$!
	start_client_log_tail

	local pid="$CLIENT_PID"
	wait_for_process_exit "$pid" "Python client"
	reap_successful_process "$pid" "Python client"
	CLIENT_PID=""
}

run_selected_client() {
	case "$CLIENT_IMPLEMENTATION" in
		c) run_c_client ;;
		node) run_node_client ;;
		python) run_python_client ;;
	esac
}

verify_c_client() {
	case "$SERVER_IMPLEMENTATION" in
		c)
			assert_log_no_errors "$SERVER_LOG" "C server"
			assert_log_no_errors "$CLIENT_LOG" "C client"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - second message"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2 - second message"
			assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client"
			assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client 2"
			;;
		node)
			assert_log_no_errors "$CLIENT_LOG" "C client"
			assert_log_contains "$SERVER_LOG" "Handler: socketID:"
			assert_log_contains "$SERVER_LOG" "data: Hello server"
			assert_log_contains "$SERVER_LOG" "data: Hello server - second message"
			assert_log_contains "$SERVER_LOG" "data: Hello server 2"
			assert_log_contains "$SERVER_LOG" "data: Hello server 2 - second message"
			;;
		python)
			assert_log_no_errors "$CLIENT_LOG" "C client"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - second message"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2 - second message"
			;;
	esac
}

verify_node_client() {
	case "$SERVER_IMPLEMENTATION" in
		c)
			assert_log_no_errors "$SERVER_LOG" "C server"
			assert_log_contains "$SERVER_LOG" "LOG: Received: data2"
			assert_log_contains "$SERVER_LOG" "Finished first communication"
			assert_log_contains "$CLIENT_LOG" "Hello client"
			;;
		node)
			assert_log_contains "$SERVER_LOG" "Handler: socketID:"
			assert_log_contains "$SERVER_LOG" "data: data2"
			assert_log_contains "$SERVER_LOG" "data: data1"
			;;
		python)
			assert_log_contains "$SERVER_LOG" "LOG: Received: data2"
			assert_log_contains "$SERVER_LOG" "LOG: Received: data1"
			;;
	esac
}

verify_python_client() {
	case "$SERVER_IMPLEMENTATION" in
		c)
			assert_log_no_errors "$SERVER_LOG" "C server"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server"
			assert_log_contains "$SERVER_LOG" "Finished first communication"
			assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client"
			;;
		node)
			assert_log_contains "$SERVER_LOG" "data: Hello server"
			assert_log_contains "$SERVER_LOG" "data: Hello server - second message"
			assert_log_contains "$SERVER_LOG" "data: Hello server - third message"
			assert_log_contains "$CLIENT_LOG" "No reply received (timeout), continuing..."
			;;
		python)
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - second message"
			assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - third message"
			assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client"
			assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client 2"
			assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client 3"
			;;
	esac
}

verify_output() {
	if [[ "$VERIFY_OUTPUT" != true ]]; then
		return
	fi

	echo "[test] Verifying $CLIENT_IMPLEMENTATION-client to $SERVER_IMPLEMENTATION-server output."
	case "$CLIENT_IMPLEMENTATION" in
		c) verify_c_client ;;
		node) verify_node_client ;;
		python) verify_python_client ;;
	esac

	if [[ "$PERMANENT_DISTRIBUTION_KEY" == true ]]; then
		echo "[test] Checking that Auth used the permanent distribution key."
		assert_log_contains "$AUTH_LOG" "Received request message encrypted with distribution key!"
	fi
}

tmux_server_command() {
	case "$SERVER_IMPLEMENTATION" in
		c)
			echo "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/c/examples/server_client_example/build") && ./entity_server ../c_server.config"
			;;
		node)
			echo "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") && node server.js configs/net1/server.config"
			;;
		python)
			case "$CLIENT_IMPLEMENTATION" in
				c)
					echo "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u py_server.py -n 2 $(quote_for_shell "$PYTHON_SERVER_CONFIG"); sleep 0.5; done"
					;;
				node)
					echo "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u py_server.py $(quote_for_shell "$PYTHON_SERVER_CONFIG"); sleep 0.5; done"
					;;
				python)
					echo "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && python3 -u py_server.py $(quote_for_shell "$PYTHON_SERVER_CONFIG")"
					;;
			esac
			;;
	esac
}

write_tmux_client_script() {
	{
		echo "#!/bin/bash"
		echo "set +e"
		echo "sleep 6"
		case "$CLIENT_IMPLEMENTATION" in
			c)
				echo "cd $(quote_for_shell "$SST_ROOT/entity/c/examples/server_client_example/build") || exit 1"
				echo "./entity_client ../c_client.config"
				echo "status=\$?"
				;;
			node)
				echo "cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") || exit 1"
				echo "node autoClient.js configs/net1/client.config &"
				echo "client_pid=\$!"
				echo "elapsed=0"
				echo "while [[ \"\$elapsed\" -lt $CLIENT_TIMEOUT ]] && kill -0 \"\$client_pid\" 2>/dev/null; do"
				echo "  sleep 1"
				echo "  elapsed=\$((elapsed + 1))"
				echo "done"
				echo "kill \"\$client_pid\" 2>/dev/null || true"
				echo "wait \"\$client_pid\" 2>/dev/null || true"
				echo "status=0"
				;;
			python)
				echo "cd $(quote_for_shell "$SST_ROOT/entity/python/examples") || exit 1"
				echo "source ../.venv/bin/activate"
				if [[ "$SERVER_IMPLEMENTATION" == "c" ]]; then
					echo "python3 py_client.py $(quote_for_shell "$PYTHON_CLIENT_CONFIG")"
					echo "status=\$?"
					echo "if [[ \"\$status\" -eq 0 ]]; then"
					echo "  sleep 2"
					echo "  python3 py_client.py $(quote_for_shell "$PYTHON_CLIENT_CONFIG")"
					echo "  status=\$?"
					echo "fi"
				else
					echo "python3 py_client.py $(quote_for_shell "$PYTHON_CLIENT_CONFIG")"
					echo "status=\$?"
				fi
				;;
		esac
		cat <<EOF
tmux send-keys -t "$AUTH_PANE_ARG" C-c
tmux send-keys -t "$SERVER_PANE_ARG" C-c
sleep 2
for port in 21900 21901 21100; do
	pids=\$(lsof -tiTCP:\$port -sTCP:LISTEN 2>/dev/null || true)
	if [[ -n "\$pids" ]]; then kill \$pids 2>/dev/null || true; fi
done
echo
echo "[test] Client finished with status \$status. Auth and server were stopped; panes remain open for inspection."
exit "\$status"
EOF
	} >"$WAIT_SCRIPT"
	chmod +x "$WAIT_SCRIPT"
}

run_tmux() {
	local client_label
	local server_label
	local password_arg
	local server_command
	client_label="$(implementation_label "$CLIENT_IMPLEMENTATION") client"
	server_label="$(implementation_label "$SERVER_IMPLEMENTATION") server"
	SESSION_NAME="sst_${CLIENT_IMPLEMENTATION}_client_${SERVER_IMPLEMENTATION}_server_test_$$"
	WAIT_SCRIPT="/tmp/${SESSION_NAME}_wait_and_stop.sh"
	password_arg="$(quote_for_shell "$AUTH_PASSWORD")"

	setup_tmux_session "$SESSION_NAME" "$server_label" "$client_label"
	write_tmux_client_script
	server_command="$(tmux_server_command)"

	tmux send-keys -t "$AUTH_PANE" "cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $password_arg" C-m
	tmux send-keys -t "$SERVER_PANE" "$server_command" C-m
	tmux send-keys -t "$CLIENT_PANE" "$(quote_for_shell "$WAIT_SCRIPT")" C-m
	attach_tmux_session "$SESSION_NAME"
}

main() {
	parse_runner_args "$@"
	validate_selection
	check_and_prepare_ports
	prepare_test
	select_python_config
	validate_python_configs

	if [[ "$USE_TMUX" == true ]]; then
		run_tmux
		return
	fi

	setup_logs "${CLIENT_IMPLEMENTATION}-client-${SERVER_IMPLEMENTATION}-server"
	if [[ "$CLIENT_IMPLEMENTATION" == "c" ]]; then
		start_error_watcher "C client" "$CLIENT_LOG"
	fi
	start_auth
	start_selected_server
	run_selected_client
	verify_output

	echo "[test] $(implementation_label "$CLIENT_IMPLEMENTATION")-client-to-$(implementation_label "$SERVER_IMPLEMENTATION")-server test passed."
}

main "$@"
