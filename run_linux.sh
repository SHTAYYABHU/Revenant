#!/usr/bin/env bash
# Starts Revenant, creating a private Python environment on the first run.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then
  echo "Creating a virtual environment in .venv, this only happens once."
  "$PY" -m venv .venv || { echo "Install the venv module first, for example: sudo apt install python3-venv"; exit 1; }
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install -r requirements.txt
fi
exec .venv/bin/python -m revenant "$@"
