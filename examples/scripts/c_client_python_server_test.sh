#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/common.sh"

usage() {
	echo "Usage: $0 [options]"
	echo
	echo "Builds, prepares, runs, and verifies the heterogeneous C-client-to-Python-server test."
	echo "Default password: 1234"
	echo
	echo "Options:"
	echo "  --password <password>       Auth password used for generation and Auth101."
	echo "  --client-timeout <seconds>  Max time for the C client. Default: 45."
	echo "  --service-timeout <seconds> Max time to wait for services. Default: 45."
	echo "  --no-build                  Skip Maven and CMake build steps."
	echo "  --no-setup                  Skip cleanAll.sh/generateAll.sh."
	echo "  --no-verify                 Run without checking server output."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop existing Auth/Python/C processes on the test ports."
	echo "  --tmux                      Show Auth, Python server, and C client in tmux panes."
	echo "  -h, --help                  Show this help message."
}

prepare_test() {
	if [[ "$RUN_BUILD" == true ]]; then
		require_command mvn
		require_command cmake
		require_command make
		require_command python3
		build_auth
		build_c_entities
		build_python_entities
	fi
	if [[ "$RUN_SETUP" == true ]]; then
		run_setup
	fi
}

parse_args "$@"
check_and_prepare_ports
prepare_test

if [[ "$USE_TMUX" == true ]]; then
	SESSION_NAME="sst_c_client_python_server_test_$$"
	WAIT_SCRIPT="/tmp/${SESSION_NAME}_wait_and_stop.sh"
	PASSWORD_ARG="$(quote_for_shell "$AUTH_PASSWORD")"
	setup_tmux_session "$SESSION_NAME" "Python server" "C client"

	cat >"$WAIT_SCRIPT" <<EOF
#!/bin/bash
set +e
sleep 6
cd $(quote_for_shell "$SST_ROOT/entity/c/examples/server_client_example/build") || exit 1
./entity_client ../c_client.config
status=\$?
tmux send-keys -t $AUTH_PANE_ARG C-c
tmux send-keys -t $SERVER_PANE_ARG C-c
sleep 2
for port in 21900 21901 21100; do
	pids=\$(lsof -tiTCP:\$port -sTCP:LISTEN 2>/dev/null || true)
	if [[ -n "\$pids" ]]; then kill \$pids 2>/dev/null || true; fi
done
echo
echo "[test] C client exited with status \$status. Auth and Python server were stopped; panes remain open for inspection."
exit "\$status"
EOF
	chmod +x "$WAIT_SCRIPT"

	tmux send-keys -t "$AUTH_PANE" "cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $PASSWORD_ARG" C-m
	tmux send-keys -t "$SERVER_PANE" "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u pyServer.py -n 2 configs/pyServer.config; done" C-m
	tmux send-keys -t "$CLIENT_PANE" "$WAIT_SCRIPT" C-m
	attach_tmux_session "$SESSION_NAME"
	exit 0
fi

setup_logs "c-client-python-server"
start_error_watcher "C client" "$CLIENT_LOG"
start_auth

echo "[test] Starting Python server in a loop to handle multiple C client connections."
start_service server bash -c \
	"cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u pyServer.py -n 2 configs/pyServer.config; sleep 0.5; done"
wait_for_port 21100 "Python server"

echo "[test] Running C client."
run_client_with_timeout

if [[ "$VERIFY_OUTPUT" == true ]]; then
	echo "[test] Checking for unexpected errors."
	assert_log_no_errors "$CLIENT_LOG" "C client"
	echo "[test] Checking Python server output."
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - second message"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server 2 - second message"
fi

echo "[test] Heterogeneous C-client-to-Python-server test passed."
