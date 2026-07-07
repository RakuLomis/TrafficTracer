# TrafficTracer Safe Start/Stop Design Spec

## Overview

Refactor TrafficTracer to be self-contained: all mihomo configs live inside the project, safe start/stop scripts handle TUN route cleanup, and dashboard code is archived to a separate branch.

## Changes

### 1. Branch management

- Create `dashboard-ver` branch from current `main` HEAD — preserves all dashboard work
- On `main`: remove dashboard code, keep core pipelines

### 2. Project structure on main

```
TrafficTracer/
├── scripts/
│   ├── start-mihomo.sh     # safe start with route backup
│   └── stop-mihomo.sh      # safe stop with route restore
├── mihomo-configs/
│   ├── config.yaml         # full proxy config + TUN + tracing
│   ├── geosite.dat
│   ├── geoip.dat
│   └── geoip.metadb
├── sites.yaml              # updated to point at mihomo-configs/
├── capture.py
├── analyze.py
├── netlog_parser.py
├── traffictracer/
├── parser/
├── test/                   # test_dashboard.py removed
├── README.md
└── docs/
```

**Removed from main:**
- `dashboard/` (all files)
- `test/test_dashboard.py`
- `run_test.sh`
- Dashboard section in README (replaced with simpler instructions)

**Added to main:**
- `scripts/start-mihomo.sh`
- `scripts/stop-mihomo.sh`
- `mihomo-configs/` directory with config + geodata files

### 3. start-mihomo.sh

```bash
#!/bin/bash
# Start mihomo-TrafficTracer with route backup for safe stop

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CFG_DIR="$PROJECT_DIR/mihomo-configs"
PID_FILE="$CFG_DIR/mihomo.pid"
ROUTE_FILE="$CFG_DIR/original-routes.txt"
MIHOMO_BIN="$PROJECT_DIR/../mihomo/bin/mihomo-linux-amd64"

# 1. Save original default routes
ip route show default > "$ROUTE_FILE" 2>/dev/null

# 2. Start mihomo
nohup "$MIHOMO_BIN" -d "$CFG_DIR" &>/tmp/mihomo-traffictracer.log &
PID=$!
echo "$PID" > "$PID_FILE"

# 3. Wait for TUN
for i in $(seq 1 10); do
    sleep 1
    if ip link show utun &>/dev/null; then
        echo "mihomo started (PID $PID), TUN ready"
        exit 0
    fi
done
echo "mihomo PID $PID, TUN may still be initializing"
```

### 4. stop-mihomo.sh

```bash
#!/bin/bash
# Safely stop mihomo-TrafficTracer — restore routes first

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CFG_DIR="$PROJECT_DIR/mihomo-configs"
PID_FILE="$CFG_DIR/mihomo.pid"
ROUTE_FILE="$CFG_DIR/original-routes.txt"

# 1. Restore original routes BEFORE killing mihomo
if [ -f "$ROUTE_FILE" ]; then
    # Delete TUN default routes
    ip route show default | while read -r line; do
        ip route del $line 2>/dev/null
    done
    # Add back original routes
    while read -r line; do
        [ -n "$line" ] && ip route add $line 2>/dev/null
    done < "$ROUTE_FILE"
    rm -f "$ROUTE_FILE"
    echo "Routes restored"
fi

# 2. Kill mihomo
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    kill "$PID" 2>/dev/null && echo "mihomo stopped (PID $PID)"
    rm -f "$PID_FILE"
else
    pkill -f "mihomo-linux-amd64" 2>/dev/null && echo "mihomo stopped"
fi
```

### 5. sites.yaml update

```yaml
global:
  mihomo:
    binary: ../mihomo/bin/mihomo-linux-amd64
    config: mihomo-configs/config.yaml
    api: "http://127.0.0.1:9099"
  # ... rest unchanged
```

Paths become relative to the project root.

### 6. README update

Replace the Dashboard section with a simple "Mihomo Management" section:

```markdown
### Start / Stop Mihomo

```bash
# Start mihomo with TUN mode (safe: saves routes for clean stop)
bash scripts/start-mihomo.sh

# Safely stop mihomo (restores original routes before killing)
bash scripts/stop-mihomo.sh
```

Mihomo config lives in `mihomo-configs/config.yaml`. Geodata files in the same directory.
```

### 7. mihomo-configs/ content

Copy from current `/tmp/mihomo-test/`:
- `config.yaml` (full proxy config with TUN + tracing + CORS + external-ui)
- `geosite.dat`
- `geoip.dat`
- `geoip.metadb`

Also generate `config.yaml` from existing config but with paths adjusted to be self-referential.

## Non-Requirements

- No dashboard code on `main`
- No metacubexd integration on `main`
- No service/systemd management (user runs scripts manually)
- No tracing API integration in scripts (just pure start/stop)
