#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/common.sh"

usage() {
	echo "Usage: $0 [options]"
	echo
	echo "Builds, prepares, runs, and verifies the heterogeneous Node-client-to-C-server test."
	echo "Default password: 1234"
	echo
	echo "Options:"
	echo "  --password <password>       Auth password used for generation and Auth101."
	echo "  --client-timeout <seconds>  Max time for the Node client. Default: 45."
	echo "  --service-timeout <seconds> Max time to wait for services. Default: 45."
	echo "  --no-build                  Skip Maven and CMake build steps."
	echo "  --no-setup                  Skip cleanAll.sh/generateAll.sh."
	echo "  --no-verify                 Run without checking output."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop existing Auth/C processes on the test ports."
	echo "  --tmux                      Show Auth, C server, and Node client in tmux panes."
	echo "                              After the exchange completes, Auth and C server are"
	echo "                              stopped while the tmux panes remain open for inspection."
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
	SESSION_NAME="sst_node_client_c_server_test_$$"
	WAIT_SCRIPT="/tmp/${SESSION_NAME}_wait_and_stop.sh"
	PASSWORD_ARG="$(quote_for_shell "$AUTH_PASSWORD")"
	setup_tmux_session "$SESSION_NAME" "C server" "Node client"

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
	if [[ -n "\$pids" ]]; then kill \$pids 2>/dev/null || true; fi
done
echo
echo "[test] Node client finished. Auth and C server were stopped; panes remain open for inspection."
EOF
	chmod +x "$WAIT_SCRIPT"

	tmux send-keys -t "$AUTH_PANE" "cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $PASSWORD_ARG" C-m
	tmux send-keys -t "$SERVER_PANE" "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/c/examples/server_client_example/build") && ./entity_server ../c_server.config" C-m
	tmux send-keys -t "$CLIENT_PANE" "$WAIT_SCRIPT" C-m
	attach_tmux_session "$SESSION_NAME"
	exit 0
fi

setup_logs "node-client-c-server"
start_error_watcher "C server" "$SERVER_LOG"
start_auth

echo "[test] Starting C server."
start_service server bash -c \
	"cd $(quote_for_shell "$SST_ROOT/entity/c/examples/server_client_example/build") && exec ./entity_server ../c_server.config"
wait_for_port 21100 "C server"

echo "[test] Starting Node client."
(
	cd "$SST_ROOT/entity/node/example_entities"
	exec node autoClient.js configs/net1/client.config
) >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
(
	tail -n +1 -f "$CLIENT_LOG" 2>/dev/null | sed -u "s/^/[client] /"
) &

echo "[test] Waiting for C server to complete both connections."
elapsed=0
while kill -0 "$SERVER_PID" 2>/dev/null; do
	if [[ "$elapsed" -ge "$CLIENT_TIMEOUT" ]]; then
		echo "[test] C server timed out after ${CLIENT_TIMEOUT}s." >&2
		exit 1
	fi
	sleep 1
	elapsed=$((elapsed + 1))
done
SERVER_PID=""

kill "$CLIENT_PID" 2>/dev/null || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

if [[ "$VERIFY_OUTPUT" == true ]]; then
	echo "[test] Checking for unexpected errors."
	assert_log_no_errors "$SERVER_LOG" "C server"
	echo "[test] Checking C server output."
	assert_log_contains "$SERVER_LOG" "LOG: Received: data2"
	assert_log_contains "$SERVER_LOG" "Finished first communication"
	echo "[test] Checking Node client output."
	assert_log_contains "$CLIENT_LOG" "Hello client"
fi

echo "[test] Heterogeneous Node-client-to-C-server test passed."
