#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$SCRIPT_DIR/common.sh"

usage() {
	echo "Usage: $0 [options]"
	echo
	echo "Builds, prepares, runs, and verifies the Python-client-to-Python-server test."
	echo "Default password: 1234"
	echo
	echo "Options:"
	echo "  --password <password>       Auth password used for generation and Auth101."
	echo "  --client-timeout <seconds>  Max time for the Python client. Default: 45."
	echo "  --service-timeout <seconds> Max time to wait for services. Default: 45."
	echo "  --no-build                  Skip build step."
	echo "  --no-setup                  Skip cleanAll.sh/generateAll.sh."
	echo "  --no-verify                 Run without checking Python server output."
	echo "  --keep-logs                 Keep logs after the test finishes."
	echo "  --stop-existing             Stop existing Auth/Python processes on the test ports."
	echo "  --tmux                      Show Auth, Python server, and Python client in tmux panes."
	echo "  -h, --help                  Show this help message."
}

prepare_test() {
	if [[ "$RUN_BUILD" == true ]]; then
		require_command mvn
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
	SESSION_NAME="sst_python_client_python_server_test_$$"
	WAIT_SCRIPT="/tmp/${SESSION_NAME}_wait_and_stop.sh"
	PASSWORD_ARG="$(quote_for_shell "$AUTH_PASSWORD")"
	setup_tmux_session "$SESSION_NAME" "Python server" "Python client"

	cat >"$WAIT_SCRIPT" <<EOF
#!/bin/bash
set +e
sleep 6
cd $(quote_for_shell "$SST_ROOT/entity/python/examples") || exit 1
source ../.venv/bin/activate
python3 pyClient.py configs/pyClient.config
status=\$?
tmux send-keys -t $AUTH_PANE_ARG C-c
tmux send-keys -t $SERVER_PANE_ARG C-c
sleep 2
for port in 21900 21901 21100; do
	pids=\$(lsof -tiTCP:\$port -sTCP:LISTEN 2>/dev/null || true)
	if [[ -n "\$pids" ]]; then kill \$pids 2>/dev/null || true; fi
done
echo
echo "[test] Python client exited with status \$status. Auth and Python server were stopped; panes remain open for inspection."
exit "\$status"
EOF
	chmod +x "$WAIT_SCRIPT"

	tmux send-keys -t "$AUTH_PANE" "cd $(quote_for_shell "$SST_ROOT/auth/auth-server") && java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $PASSWORD_ARG" C-m
	tmux send-keys -t "$SERVER_PANE" "sleep 3 && cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && python3 pyServer.py configs/pyServer.config" C-m
	tmux send-keys -t "$CLIENT_PANE" "$WAIT_SCRIPT" C-m
	attach_tmux_session "$SESSION_NAME"
	exit 0
fi

setup_logs "python-client-python-server"
start_auth

echo "[test] Starting Python server."
start_service server bash -c \
	"cd $(quote_for_shell "$SST_ROOT/entity/python/examples") && source ../.venv/bin/activate && exec python3 pyServer.py configs/pyServer.config"
wait_for_port 21100 "Python server"

echo "[test] Running Python client."
(
	cd "$SST_ROOT/entity/python/examples"
	source ../.venv/bin/activate
	exec python3 pyClient.py configs/pyClient.config
) >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
(
	tail -n +1 -f "$CLIENT_LOG" 2>/dev/null | sed -u "s/^/[client] /"
) &

echo "[test] Waiting for Python client to complete."
elapsed=0
while kill -0 "$CLIENT_PID" 2>/dev/null; do
	if [[ "$elapsed" -ge "$CLIENT_TIMEOUT" ]]; then
		echo "[test] Python client timed out after ${CLIENT_TIMEOUT}s." >&2
		kill "$CLIENT_PID" 2>/dev/null || true
		exit 1
	fi
	sleep 1
	elapsed=$((elapsed + 1))
done

wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

if [[ "$VERIFY_OUTPUT" == true ]]; then
	echo "[test] Checking Python server output."
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - second message"
	assert_log_contains "$SERVER_LOG" "LOG: Received: Hello server - third message"
	echo "[test] Checking Python client output."
	assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client"
	assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client 2"
	assert_log_contains "$CLIENT_LOG" "LOG: Received: Hello client 3"
fi

echo "[test] Python-client-to-Python-server test passed."
