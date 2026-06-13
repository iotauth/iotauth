#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/common.sh"

usage() {
	echo "Usage: $0 [options]"
	echo
	echo "Builds, prepares, runs, and verifies the heterogeneous C-client-to-Node-server test."
	echo "Default password: 1234"
	echo
	echo "Options:"
	echo "  --password <password>       Auth password used for generation and Auth101."
	echo "  --client-timeout <seconds>  Max time for the C client. Default: 45."
	echo "  --service-timeout <seconds> Max time to wait for services. Default: 45."
	echo "  --no-build                  Skip Maven and CMake build steps."
	echo "  --no-setup                  Skip cleanAll.sh/generateAll.sh."
	echo "  --no-verify                 Run without checking Node server output."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop existing Auth/Node processes on the test ports."
	echo "  --tmux                      Show Auth, Node, and C client in tmux panes."
	echo "                              After the C client exits, Auth and Node are stopped"
	echo "                              while the tmux panes remain open for inspection."
	echo "  -h, --help                  Show this help message."
}

prepare_test() {
	if [[ "$RUN_BUILD" == true ]]; then
		require_command mvn
		require_command cmake
		require_command make
		require_command node
		require_command npm
		build_auth
		build_c_entities
	fi
	if [[ "$RUN_SETUP" == true ]]; then
		run_setup
	fi
}

parse_args "$@"
check_and_prepare_ports
prepare_test

if [[ "$USE_TMUX" == true ]]; then
	SESSION_NAME="sst_c_client_node_server_test_$$"
	WAIT_SCRIPT="/tmp/${SESSION_NAME}_wait_and_stop.sh"
	PASSWORD_ARG="$(quote_for_shell "$AUTH_PASSWORD")"
	setup_tmux_session "$SESSION_NAME" "Node server" "C client"

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
echo "[test] C client exited with status \$status. Auth and Node were stopped; panes remain open for inspection."
exit "\$status"
EOF
	chmod +x "$WAIT_SCRIPT"

	tmux send-keys -t "$AUTH_PANE" "cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $PASSWORD_ARG" C-m
	tmux send-keys -t "$SERVER_PANE" "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") && node server.js configs/net1/server.config" C-m
	tmux send-keys -t "$CLIENT_PANE" "$WAIT_SCRIPT" C-m
	attach_tmux_session "$SESSION_NAME"
	exit 0
fi

setup_logs "c-client-node-server"
start_error_watcher "C client" "$CLIENT_LOG"
start_auth

echo "[test] Starting Node.js server."
start_service server bash -c \
	"cd $(quote_for_shell "$SST_ROOT/entity/node/example_entities") && exec node server.js configs/net1/server.config"
wait_for_log "$SERVER_LOG" "Handler: listening on port" "Node.js server"

echo "[test] Running C client."
run_client_with_timeout

if [[ "$VERIFY_OUTPUT" == true ]]; then
	echo "[test] Checking for unexpected errors."
	assert_log_no_errors "$CLIENT_LOG" "C client"
	echo "[test] Checking Node.js server output."
	assert_log_contains "$SERVER_LOG" "Handler: socketID:"
	assert_log_contains "$SERVER_LOG" "data: Hello server"
	assert_log_contains "$SERVER_LOG" "data: Hello server - second message"
	assert_log_contains "$SERVER_LOG" "data: Hello server 2"
	assert_log_contains "$SERVER_LOG" "data: Hello server 2 - second message"
fi

echo "[test] Heterogeneous C-client-to-Node-server test passed."
