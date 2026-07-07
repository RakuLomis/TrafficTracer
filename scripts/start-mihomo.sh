#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CFG_DIR="$PROJECT_DIR/mihomo-configs"
PID_FILE="$CFG_DIR/mihomo.pid"
ROUTE_FILE="$CFG_DIR/original-routes.txt"

MIHOMO_BIN="$PROJECT_DIR/../mihomo/bin/mihomo-traffictracer"

if [ ! -f "$MIHOMO_BIN" ]; then
    echo "ERROR: mihomo binary not found at $MIHOMO_BIN"
    exit 1
fi

# Save original default routes
ip route show default > "$ROUTE_FILE" 2>/dev/null
echo "Original routes saved to $ROUTE_FILE"

# Start mihomo
nohup "$MIHOMO_BIN" -d "$CFG_DIR" &>/tmp/mihomo-traffictracer.log &
PID=$!
echo "$PID" > "$PID_FILE"
echo "mihomo started (PID $PID)"

# Wait for TUN device
for i in $(seq 1 10); do
    sleep 1
    if ip link show utun &>/dev/null; then
        echo "TUN device utun ready"
        exit 0
    fi
done
echo "TUN device not detected after 10s, mihomo may still be initializing"
