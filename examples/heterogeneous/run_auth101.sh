#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SST_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AUTH_PASSWORD="1234"

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
		-h|--help)
			echo "Usage: $0 [--password <password>]"
			echo
			echo "Starts Auth101 for the heterogeneous example."
			echo "Default password: 1234"
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			echo "Usage: $0 [--password <password>]" >&2
			exit 1
			;;
	esac
	shift
done

cd "$SST_ROOT/auth/auth-server"
java -jar target/auth-server-jar-with-dependencies.jar \
	-p ../properties/exampleAuth101.properties \
	--password="$AUTH_PASSWORD"
