#!/bin/bash
# Hanirizer CLI Runner
# This script runs hanirizer from source

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set PYTHONPATH to include the project root
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

# Run using python module syntax
cd "$SCRIPT_DIR"
python3 -m src.cli "$@"
