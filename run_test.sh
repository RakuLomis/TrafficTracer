#!/bin/bash
# ============================================================
# TrafficTracer 完整流量捕捉与关联测试
# 目标: www.bilibili.com, 15s, traffic_type=video-mainpage
# 输出: /data/datasets/ttTest-0705
# ============================================================
set -e

TRACER_DIR="/data/ytluo/projects/TrafficTracer"
MIHOMO_BIN="/data/ytluo/projects/mihomo/bin/mihomo-linux-amd64"
MIHOMO_CONF_DIR="/tmp/mihomo-test"
OUTPUT_BASE="/data/datasets/ttTest-0705"

echo "############################################################"
echo "# TrafficTracer 测试 — $(date)"
echo "############################################################"

# ——— Step 0: 清理上次残留 ———
echo ""
echo "=== Step 0: Cleanup ==="
pkill -f "mihomo-linux-amd64" 2>/dev/null || true
sleep 0.5

# ——— Step 1: 验证配置 ———
echo ""
echo "=== Step 1: Validate mihomo config ==="
$MIHOMO_BIN -t -d $MIHOMO_CONF_DIR
echo "  Config OK"

# ——— Step 2: 停止 verge-mihomo ———
echo ""
echo "=== Step 2: Stop verge-mihomo ==="
VERGE_PID=$(pgrep -f "verge-mihomo" | head -1)
if [ -n "$VERGE_PID" ]; then
    echo "  Killing verge-mihomo (PID: $VERGE_PID)"
    kill $VERGE_PID 2>/dev/null
    sleep 1
    if ps -p $VERGE_PID > /dev/null 2>&1; then
        echo "  Force killing..."
        kill -9 $VERGE_PID 2>/dev/null
        sleep 0.5
    fi
    echo "  verge-mihomo stopped"
else
    echo "  verge-mihomo not running"
fi

# ——— Step 3: 运行 Capture Pipeline ———
echo ""
echo "=== Step 3: Run capture pipeline ==="
cd $TRACER_DIR
python3 capture.py --config sites.yaml --only bilibili.com

# ——— Step 4: 运行 Analysis Pipeline ———
echo ""
echo "=== Step 4: Run analysis pipeline ==="
SESSION_DIR=$(ls -td $OUTPUT_BASE/*/ 2>/dev/null | head -1)
if [ -z "$SESSION_DIR" ]; then
    echo "ERROR: No session directory found under $OUTPUT_BASE"
    exit 1
fi
echo "  Session: $SESSION_DIR"
python3 analyze.py --session "$SESSION_DIR"

# ——— Step 5: 恢复 verge-mihomo ———
echo ""
echo "=== Step 5: Restart verge-mihomo ==="
if pgrep -f "clash-verge$" > /dev/null 2>&1; then
    echo "  clash-verge GUI is still running, waiting for it to restart mihomo..."
    sleep 3
    if pgrep -f "verge-mihomo" > /dev/null; then
        echo "  verge-mihomo auto-restarted"
    else
        echo "  verge-mihomo not restarted, starting manually..."
        /usr/bin/verge-mihomo -d /home/ytluo/.local/share/io.github.clash-verge-rev.clash-verge-rev \
            -f /home/ytluo/.local/share/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml \
            -ext-ctl-unix /tmp/verge/verge-mihomo.sock &>/dev/null &
        sleep 2
    fi
else
    echo "  clash-verge GUI not running"
    /usr/bin/verge-mihomo -d /home/ytluo/.local/share/io.github.clash-verge-rev.clash-verge-rev \
        -f /home/ytluo/.local/share/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml \
        -ext-ctl-unix /tmp/verge/verge-mihomo.sock &>/dev/null &
    sleep 2
fi

# ——— Step 6: 输出摘要 ———
echo ""
echo "############################################################"
echo "# 测试完成 — $(date)"
echo "#"
echo "# Session: $SESSION_DIR"
echo "#"
ls -la "$SESSION_DIR/captures/bilibili.com/" 2>/dev/null
echo ""
ls -la "$SESSION_DIR/logs/" 2>/dev/null
echo ""
if [ -f "$SESSION_DIR/results/correlation.json" ]; then
    echo "# correlation.json:"
    python3 -c "
import json
with open('$SESSION_DIR/results/correlation.json') as f:
    data = json.load(f)
for domain, flows in data.items():
    print(f'  {domain}: {len(flows)} flows correlated')
" 2>/dev/null || echo "  (unable to parse correlation)"
fi
echo "############################################################"
