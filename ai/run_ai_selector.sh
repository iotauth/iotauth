#!/bin/bash

# ==============================================================================
# Execution Script for Physical Context Challenge Selector Server (Gemma LLM)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

MODEL_NAME="${1:-google/gemma-2-2b-it}"
PORT="${2:-8000}"
MOCK_FLAG=""

if [ "$1" == "--mock" ] || [ "$3" == "--mock" ]; then
    MOCK_FLAG="--mock"
fi

echo "======================================================================"
echo " Physical Context Challenge Selector Server"
echo " Model: $MODEL_NAME"
echo " Port:  $PORT"
echo " Mode:  ${MOCK_FLAG:-GPU / Transformers}"
echo "======================================================================"

python3 selector_server.py --model "$MODEL_NAME" --port "$PORT" $MOCK_FLAG
