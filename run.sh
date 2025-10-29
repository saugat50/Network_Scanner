#!/usr/bin/env bash
set -e
MODE="${1:-gui}"

VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
if [ -f requirements.txt ]; then
  pip install -r requirements.txt || true
fi

if [ "$MODE" = "gui" ]; then
  echo "Launching GUI (src/scanner.py) ..."
  python3 src/scanner.py
elif [ "$MODE" = "cli" ]; then
  echo "Launching CLI (src/cli_main.py) ..."
  python3 src/cli_main.py --host 127.0.0.1 --ports 22,80
else
  echo "Unknown mode: $MODE"
  exit 2
fi
