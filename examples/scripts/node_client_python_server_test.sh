#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/common.sh"

usage() {
	echo "Usage: $0 [options]"
	echo
	echo "Builds, prepares, runs, and verifies the heterogeneous Node-client-to-Python-server test."
	echo "Default password: 1234"
	echo
	echo "Options:"
	echo "  --password <password>       Auth password used for generation and Auth101."
	echo "  --client-timeout <seconds>  Max time for the Node client. Default: 45."
	echo "  --service-timeout <seconds> Max time to wait for services. Default: 45."
	echo "  --no-build                  Skip Maven build step."
	echo "  --no-setup                  Skip cleanAll.sh/generateAll.sh."
	echo "  --no-verify                 Run without checking Python server output."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop existing Auth/Node/Python processes on the test ports."
	echo "  --tmux                      Show Auth, Python server, and Node client in tmux panes."
	echo "  -h, --help                  Show this help message."
}

prepare_test() {
	if [[ "$RUN_BUILD" == true ]]; then
		require_command mvn
		require_command node
		require_command npm
		require_command python3
		build_auth
	fi
	if [[ "$RUN_SETUP" == true ]]; then
		run_setup
	fi
	build_python_entities
}

parse_args "$@"
check_and_prepare_ports
prepare_test

if [[ "$USE_TMUX" == true ]]; then
	SESSION_NAME="sst_node_client_python_server_test_$$"
	WAIT_SCRIPT="/tmp/${SESSION_NAME}_wait_and_stop.sh"
	PASSWORD_ARG="$(quote_for_shell "$AUTH_PASSWORD")"
	setup_tmux_session "$SESSION_NAME" "Python server" "Node client"

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
echo "[test] Node client finished. Auth and Python server were stopped; panes remain open for inspection."
EOF
	chmod +x "$WAIT_SCRIPT"

	tmux send-keys -t "$AUTH_PANE" "cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $PASSWORD_ARG" C-m
	tmux send-keys -t "$SERVER_PANE" "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u pyServer.py configs/pyServer.config; done" C-m
	tmux send-keys -t "$CLIENT_PANE" "$WAIT_SCRIPT" C-m
	attach_tmux_session "$SESSION_NAME"
	exit 0
fi

setup_logs "node-client-python-server"
start_auth

echo "[test] Starting Python server."
start_service server bash -c \
	"cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && while true; do python3 -u pyServer.py configs/pyServer.config; sleep 0.5; done"
wait_for_port 21100 "Python server"

echo "[test] Starting Node client."
(
	cd "$SST_ROOT/entity/node/example_entities"
	exec node autoClient.js configs/net1/client.config
) >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
(
	tail -n +1 -f "$CLIENT_LOG" 2>/dev/null | sed -u "s/^/[client] /"
) &

echo "[test] Waiting for Python server to receive both messages."
elapsed=0
while [[ "$elapsed" -lt "$CLIENT_TIMEOUT" ]]; do
	if grep -Fq "LOG: Received: data1" "$SERVER_LOG" 2>/dev/null; then
		break
	fi
	sleep 1
	elapsed=$((elapsed + 1))
done

if ! grep -Fq "LOG: Received: data1" "$SERVER_LOG" 2>/dev/null; then
	echo "[test] Timed out waiting for Python server to receive messages." >&2
	exit 1
fi

kill "$CLIENT_PID" 2>/dev/null || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

if [[ "$VERIFY_OUTPUT" == true ]]; then
	echo "[test] Checking Python server output."
	assert_log_contains "$SERVER_LOG" "LOG: Received: data2"
	assert_log_contains "$SERVER_LOG" "LOG: Received: data1"
fi

echo "[test] Heterogeneous Node-client-to-Python-server test passed."
