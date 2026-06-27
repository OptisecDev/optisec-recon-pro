#!/bin/bash
# OPTISEC Recon Pro — Startup Script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ ! -d "venv" ]; then
  echo "[*] Creating virtual environment..."
  python -m venv venv
  venv/bin/pip install -q -r requirements.txt
fi

if [ -f ".env" ]; then
  export $(grep -v '^#' .env | xargs)
fi

case "$1" in
  web|dashboard)
    echo "[*] Starting web dashboard at http://localhost:8000"
    venv/bin/python -m uvicorn web.app:app --host 0.0.0.0 --port 8000 --reload
    ;;
  cli|"")
    echo "[*] Starting CLI..."
    venv/bin/python cli/main.py
    ;;
  scan)
    shift
    venv/bin/python main.py scan "$@"
    ;;
  *)
    echo "Usage: $0 [web|cli|scan <target>]"
    ;;
esac
