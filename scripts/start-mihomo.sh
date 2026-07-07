#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITES_YAML="$PROJECT_DIR/sites.yaml"

# Read binary and config paths from sites.yaml
MIHOMO_BIN=$(python3 -c "
import yaml, os
with open('$SITES_YAML') as f:
    cfg = yaml.safe_load(f)
path = cfg['global']['mihomo']['binary']
if not os.path.isabs(path):
    path = os.path.join('$PROJECT_DIR', path)
print(os.path.normpath(path))
")

CFG_PATH=$(python3 -c "
import yaml, os
with open('$SITES_YAML') as f:
    cfg = yaml.safe_load(f)
path = cfg['global']['mihomo']['config']
if not os.path.isabs(path):
    path = os.path.join('$PROJECT_DIR', path)
print(os.path.normpath(path))
")
CFG_DIR="$(dirname "$CFG_PATH")"

PID_FILE="$CFG_DIR/mihomo.pid"
ROUTE_FILE="$CFG_DIR/original-routes.txt"

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
