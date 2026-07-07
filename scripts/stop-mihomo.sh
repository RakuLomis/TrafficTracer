#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CFG_DIR="$PROJECT_DIR/mihomo-configs"
PID_FILE="$CFG_DIR/mihomo.pid"
ROUTE_FILE="$CFG_DIR/original-routes.txt"

# Restore original routes BEFORE killing mihomo
if [ -f "$ROUTE_FILE" ]; then
    # Remove current TUN-routed defaults
    ip route show default 2>/dev/null | while read -r line; do
        ip route del $line 2>/dev/null || true
    done
    # Add back original routes
    while read -r line; do
        [ -n "$line" ] && ip route add $line 2>/dev/null || true
    done < "$ROUTE_FILE"
    rm -f "$ROUTE_FILE"
    echo "Original routes restored"
else
    echo "WARNING: no saved routes found at $ROUTE_FILE"
fi

# Kill mihomo
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill "$PID" 2>/dev/null; then
        echo "mihomo stopped (PID $PID)"
    fi
    rm -f "$PID_FILE"
else
    pkill -f "mihomo-traffictracer" 2>/dev/null && echo "mihomo stopped" || echo "No mihomo process found"
fi
