#!/bin/bash

# Initialize Python example entities (venv installation)
echo "Setting up Python virtual environment for example python entities ..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -e .
deactivate
