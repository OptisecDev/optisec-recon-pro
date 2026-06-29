#!/usr/bin/env bash
# OPTISEC Recon Pro — System Launcher

set -euo pipefail

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/venv"
HOST="0.0.0.0"
PORT=8000
URL="http://localhost:$PORT"

# ─── Colors ───────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════╗"
    echo "║  ██████  ██████  ████████ ██  ██      ║"
    echo "║ ██    ██ ██   ██    ██    ██ ██       ║"
    echo "║ ██    ██ ██████     ██    ████        ║"
    echo "║ ██    ██ ██         ██    ██ ██       ║"
    echo "║  ██████  ██         ██    ██  ██      ║"
    echo "╠═══════════════════════════════════════╣"
    echo "║  OPTISEC Recon Pro v3.0               ║"
    echo "║  Enterprise Security Platform         ║"
    echo "║  By: Engineer Ihsan Ali               ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ─── Status line ──────────────────────────────────────────────────────────────
status()  { echo -e "  ${GREEN}▶${RESET}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
error()   { echo -e "  ${RED}✖${RESET}  $*" >&2; }
section() { echo -e "\n  ${BOLD}${DIM}$*${RESET}"; }

# ─── Pre-flight ───────────────────────────────────────────────────────────────
check_venv() {
    if [[ ! -f "$VENV/bin/activate" ]]; then
        error "Virtual environment not found at $VENV"
        echo -e "  Run: ${CYAN}python3 -m venv $VENV && $VENV/bin/pip install -r $SCRIPT_DIR/requirements.txt${RESET}"
        exit 1
    fi
}

check_port() {
    if ss -tlnp 2>/dev/null | grep -q ":$PORT " || \
       lsof -ti ":$PORT" &>/dev/null 2>&1; then
        warn "Port $PORT is already in use."
        echo -e "  Kill it with: ${CYAN}fuser -k ${PORT}/tcp${RESET}"
        exit 1
    fi
}

get_local_ip() {
    ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "N/A"
}

open_browser() {
    local target="$1"
    # Wait for server to accept connections (max 10 s)
    local tries=0
    while ! curl -sf --max-time 1 "$target" >/dev/null 2>&1; do
        sleep 0.5
        (( tries++ ))
        if (( tries >= 20 )); then
            warn "Server did not respond in time — skipping browser open."
            return
        fi
    done
    if command -v firefox &>/dev/null; then
        firefox "$target" &>/dev/null &
    elif command -v xdg-open &>/dev/null; then
        xdg-open "$target" &>/dev/null &
    else
        warn "No browser launcher found. Open manually: $target"
    fi
}

# ─── Shutdown handler ─────────────────────────────────────────────────────────
cleanup() {
    echo ""
    warn "Shutting down OPTISEC Recon Pro…"
    # Kill background uvicorn if this script owns it
    [[ -n "${UVICORN_PID:-}" ]] && kill "$UVICORN_PID" 2>/dev/null || true
    status "Goodbye."
    exit 0
}
trap cleanup SIGINT SIGTERM

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    clear
    print_banner

    section "System Information"
    status "Date/Time : $(date '+%Y-%m-%d %H:%M:%S %Z')"
    status "Project   : $SCRIPT_DIR"
    status "Python    : $("$VENV/bin/python" --version 2>&1 | awk '{print $2}')"
    status "User      : $(whoami)"

    section "Pre-flight Checks"
    check_venv  && status "Virtual environment  ${GREEN}OK${RESET}"
    check_port  && status "Port $PORT             ${GREEN}FREE${RESET}"

    section "Activating Environment"
    # shellcheck source=/dev/null
    source "$VENV/bin/activate"
    status "venv activated"

    # Load .env if present
    if [[ -f "$SCRIPT_DIR/.env" ]]; then
        set -o allexport
        source "$SCRIPT_DIR/.env"
        set +o allexport
        status ".env loaded"
    fi

    section "Starting Server"
    cd "$SCRIPT_DIR"

    local local_ip
    local_ip="$(get_local_ip)"

    echo ""
    echo -e "  ${CYAN}${BOLD}Active URLs:${RESET}"
    echo -e "  ${GREEN}▸${RESET}  Local        →  ${CYAN}http://localhost:$PORT${RESET}"
    echo -e "  ${GREEN}▸${RESET}  Network      →  ${CYAN}http://$local_ip:$PORT${RESET}"
    echo -e "  ${GREEN}▸${RESET}  API Docs     →  ${CYAN}http://localhost:$PORT/docs${RESET}"
    echo -e "  ${GREEN}▸${RESET}  ReDoc        →  ${CYAN}http://localhost:$PORT/redoc${RESET}"
    echo ""
    echo -e "  ${DIM}Press Ctrl+C to stop the server${RESET}"
    echo ""

    # Open browser in background after server is ready
    open_browser "$URL" &

    # Start uvicorn — foreground so logs stream to terminal
    uvicorn web.app:app \
        --host "$HOST" \
        --port "$PORT" \
        --reload \
        --reload-dir "$SCRIPT_DIR/web" \
        --reload-dir "$SCRIPT_DIR/modules" \
        --log-level info &
    UVICORN_PID=$!
    wait "$UVICORN_PID"
}

main "$@"
