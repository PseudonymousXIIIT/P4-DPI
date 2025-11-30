#!/usr/bin/env bash
# Helper script to cleanly start the P4 DPI system with Scapy traffic
# Usage:
#   ./scripts/start_scapy_dpi.sh                # uses default PACKET_LIMIT=600
#   PACKET_LIMIT=800 ./scripts/start_scapy_dpi.sh
#   PACKET_LIMIT=0   ./scripts/start_scapy_dpi.sh  # unlimited traffic
# After start you can run: python3 scripts/check_ipv6.py

set -euo pipefail
PACKET_LIMIT=${PACKET_LIMIT:-600}
LOG_DIR="logs"
DB_PATH="$LOG_DIR/packets.db"
DPI_LOG="$LOG_DIR/dpi.log"

cleanup() {
  echo "[CLEANUP] Killing old processes..." >&2
  pkill -9 -f start_dpi.py || true
  pkill -9 -f simple_switch_grpc || true
  sleep 1
  local remaining
  remaining=$(ps aux | grep -E 'start_dpi.py|simple_switch_grpc' | grep -v grep || true)
  if [ -n "$remaining" ]; then
    echo "$remaining" | awk '{print $2}' | xargs -r kill -9 || true
  fi
  echo "[CLEANUP] Clearing Mininet state..." >&2
  mn -c >/dev/null 2>&1 || true
  echo "[CLEANUP] Removing old DB/logs..." >&2
  rm -f "$DB_PATH" "$DPI_LOG"
  echo "[CLEANUP] Done." >&2
}

start() {
  echo "[START] PACKET_LIMIT=$PACKET_LIMIT (0 = unlimited)" >&2
  export DPI_TRAFFIC_TARGET_PACKETS="$PACKET_LIMIT"
  # Start in foreground; user can Ctrl+C or disown externally
  python3 scripts/start_dpi.py --mode start &
  DPI_PID=$!
  echo "[START] start_dpi.py PID=$DPI_PID" >&2
  sleep 5  # Wait for DPI to initialize before printing monitor instructions
}

# monitor_hint() {
#   cat <<EOF
# [INFO] Startup initiated.
# Run these for monitoring:
#   docker exec p4-dpi-container python3 scripts/check_db.py
#   docker exec p4-dpi-container python3 scripts/check_ipv6.py
# Stop all processes:
#   docker exec p4-dpi-container bash -lc "pkill -9 -f start_dpi.py; pkill -9 -f simple_switch_grpc"
# EOF
# }

cleanup
start
# monitor_hint
