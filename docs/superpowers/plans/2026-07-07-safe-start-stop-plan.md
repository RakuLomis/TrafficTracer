# TrafficTracer Safe Start/Stop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor TrafficTracer to be self-contained: mihomo configs live inside the project, safe start/stop scripts handle TUN route cleanup, dashboard code archived to a separate branch.

**Architecture:** Two shell scripts manage the mihomo lifecycle — `start-mihomo.sh` saves original routes before starting TUN mode, `stop-mihomo.sh` restores them before killing the process. All mihomo config files live under `mihomo-configs/`.

**Tech Stack:** bash, iproute2, git branch management

## Global Constraints

- Do NOT disrupt the currently running verge-mihomo proxy
- All mihomo configs must be inside the project (no /tmp/ dependencies)
- Scripts use absolute paths derived from the script's own location
- Dashboard code preserved on `dashboard-ver` branch, removed from `main`
- No new Python dependencies for start/stop scripts

---

### Task 1: Create dashboard-ver branch and clean up main

**Files:**
- Modify: main branch — remove dashboard code

- [ ] **Step 1: Create dashboard-ver branch from current HEAD**

```bash
cd /data/ytluo/projects/TrafficTracer
git branch dashboard-ver
echo "dashboard-ver branch created from main"
```

- [ ] **Step 2: Remove dashboard code from main**

```bash
git checkout main || true
rm -rf dashboard/
rm -f test/test_dashboard.py
rm -f run_test.sh
```

- [ ] **Step 3: Commit empty untracked docs**

```bash
git add docs/superpowers/specs/2026-07-05-traffictracer-dashboard-design.md \
        docs/superpowers/specs/2026-07-06-metacubexd-tracing-toggle-design.md \
        docs/superpowers/plans/2026-07-05-traffictracer-dashboard-plan.md \
        docs/superpowers/plans/2026-07-06-metacubexd-tracing-toggle-plan.md \
        docs/superpowers/specs/2026-07-07-safe-start-stop-design.md
git add -u
git commit -m "refactor: remove dashboard code, preserved on dashboard-ver branch"
```

- [ ] **Step 4: Verify cleanup**

```bash
ls dashboard/ 2>/dev/null && echo "ERROR: dashboard still exists" || echo "dashboard removed OK"
ls test/test_dashboard.py 2>/dev/null && echo "ERROR: test_dashboard.py still exists" || echo "test_dashboard removed OK"
```

---

### Task 2: Create mihomo-configs/ with config and geodata

**Files:**
- Create: `mihomo-configs/config.yaml`
- Create: `mihomo-configs/geosite.dat`
- Create: `mihomo-configs/geoip.dat`
- Create: `mihomo-configs/geoip.metadb`

- [ ] **Step 1: Create mihomo-configs/ and copy config**

```bash
mkdir -p mihomo-configs
cp /tmp/mihomo-test/config.yaml mihomo-configs/config.yaml
```

- [ ] **Step 2: Copy geodata files**

```bash
cp /tmp/mihomo-test/geosite.dat mihomo-configs/
cp /tmp/mihomo-test/geoip.dat mihomo-configs/
cp /tmp/mihomo-test/geoip.metadb mihomo-configs/
```

- [ ] **Step 3: Remove external-ui from config (dashboard not on main)**

Look for these lines in `mihomo-configs/config.yaml` and remove them:
```yaml
external-ui: /tmp/mihomo-test/ui
external-controller-cors:
  allow-origins:
    - "*"
  allow-private-network: true
```

- [ ] **Step 4: Commit**

```bash
git add mihomo-configs/
git commit -m "feat: add self-contained mihomo config with geodata"
```

---

### Task 3: Create safe start/stop scripts

**Files:**
- Create: `scripts/start-mihomo.sh`
- Create: `scripts/stop-mihomo.sh`

- [ ] **Step 1: Create `scripts/start-mihomo.sh`**

```bash
#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CFG_DIR="$PROJECT_DIR/mihomo-configs"
PID_FILE="$CFG_DIR/mihomo.pid"
ROUTE_FILE="$CFG_DIR/original-routes.txt"

MIHOMO_BIN="$PROJECT_DIR/../mihomo/bin/mihomo-linux-amd64"

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
```

- [ ] **Step 2: Create `scripts/stop-mihomo.sh`**

```bash
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
    pkill -f "mihomo-linux-amd64" 2>/dev/null && echo "mihomo stopped" || echo "No mihomo process found"
fi
```

- [ ] **Step 3: Make scripts executable**

```bash
chmod +x scripts/start-mihomo.sh scripts/stop-mihomo.sh
```

- [ ] **Step 4: Commit**

```bash
git add scripts/
git commit -m "feat: add safe mihomo start/stop scripts with route backup"
```

---

### Task 4: Update sites.yaml, README, and verify

**Files:**
- Modify: `sites.yaml` — update mihomo binary and config paths
- Modify: `README.md` — replace dashboard section with simple management section

- [ ] **Step 1: Update sites.yaml paths**

Change the mihomo section to use relative paths:

```yaml
global:
  mihomo:
    binary: ../mihomo/bin/mihomo-linux-amd64
    config: mihomo-configs/config.yaml
```

Remove the trailing line `external-controller-cors:` section that was added to the mihomo config (if present at end).

- [ ] **Step 2: Update README**

Replace the Dashboard section (from `### Dashboard` to the end of the dashboard content, before `## Mihomo Proxy Operations`) with:

```markdown
### Start / Stop Mihomo

```bash
# Start mihomo with TUN mode (saves original routes for safe stop)
bash scripts/start-mihomo.sh

# Safely stop mihomo (restores original routes before killing)
bash scripts/stop-mihomo.sh
```

Mihomo config files live in `mihomo-configs/` — all self-contained within the project.
```

Also remove the `python-multipart` reference if any remains in the install section.

- [ ] **Step 3: Commit**

```bash
git add sites.yaml README.md
git commit -m "docs: update config paths and README for self-contained setup"
```
