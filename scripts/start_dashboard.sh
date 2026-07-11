#!/usr/bin/env bash
#
# Aegis — one-shot dashboard launcher (no tmux/screen required).
#
# Fully detaches every process (nohup, disown, all fds redirected including
# stdin) so nothing is tied to this terminal's controlling tty. The script
# launches everything, prints status, and EXITS — handing your terminal
# back immediately. Servers keep running after the script returns.
#
# Usage:
#   chmod +x scripts/start_dashboard.sh
#   ./scripts/start_dashboard.sh
#
# Stop everything later with:
#   ./scripts/stop_dashboard.sh

set -uo pipefail
cd "$(dirname "$0")/.."   # repo root, regardless of where this is called from

SANDBOX_PORT=8001
OPS_PORT=3000
ATTACK_INTERVAL_S=25
PIDFILE=/tmp/aegis_pids.txt

echo "=== Aegis Dashboard Launcher (detached mode) ==="
echo ""

# ── 0. Sanity checks ────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    echo "[!] No .env found. Copying .env.example — edit it with your LLM endpoint if needed."
    cp .env.example .env
fi

if ! python3 -c "import fastapi, uvicorn" 2>/dev/null; then
    echo "[*] Installing Python dependencies..."
    pip install -r requirements.txt --break-system-packages -q
fi

# Clear any PIDs from a previous run so stop_dashboard.sh doesn't try to
# kill processes that no longer exist / belong to a different run.
> "$PIDFILE"

launch() {
    # $1 = human label, remaining args = command to run
    local label="$1"; shift
    if command -v setsid > /dev/null; then
        # setsid fully detaches from the controlling terminal at the OS
        # level (new session, no tty) — the most robust option, standard
        # on every Linux box, no install needed.
        setsid "$@" </dev/null > "/tmp/aegis_${label}.log" 2>&1 &
    else
        nohup "$@" </dev/null > "/tmp/aegis_${label}.log" 2>&1 &
    fi
    local pid=$!
    disown "$pid" 2>/dev/null || disown
    echo "$pid" >> "$PIDFILE"
    echo "[*] ${label} started (pid ${pid}), log: /tmp/aegis_${label}.log"
}

# ── 1. Sandbox app ───────────────────────────────────────────────────
launch sandbox python3 -m uvicorn src.sandbox_target.app:app \
    --port "${SANDBOX_PORT}" --host 0.0.0.0

# ── 2. Ops dashboard server ──────────────────────────────────────────
launch ops python3 -m uvicorn src.agents.ops_server:ops_app \
    --port "${OPS_PORT}" --host 0.0.0.0

sleep 3

if ! curl -sf "http://localhost:${SANDBOX_PORT}/ping" > /dev/null; then
    echo "[!] Sandbox app failed to start. Last 20 lines of log:"
    tail -20 /tmp/aegis_sandbox.log
    exit 1
fi
if ! curl -sf "http://localhost:${OPS_PORT}/" > /dev/null; then
    echo "[!] Ops server failed to start. Last 20 lines of log:"
    tail -20 /tmp/aegis_ops.log
    exit 1
fi
echo "[+] Both servers are up."

# ── 3. Point attack.py at the right port ────────────────────────────
if grep -q "^TARGET = " scripts/attack.py; then
    sed -i "s|^TARGET = .*|TARGET = \"http://localhost:${SANDBOX_PORT}\"|" scripts/attack.py
    sed -i "s|^TARGET_LOOPBACK = .*|TARGET_LOOPBACK = \"http://127.0.0.1:${SANDBOX_PORT}\"|" scripts/attack.py
fi

# ── 4. Background traffic generator loop ────────────────────────────
cat > /tmp/aegis_attack_loop.sh <<EOF
#!/usr/bin/env bash
while true; do
    python3 "$(pwd)/scripts/attack.py" >> /tmp/aegis_attack.log 2>&1
    sleep ${ATTACK_INTERVAL_S}
done
EOF
chmod +x /tmp/aegis_attack_loop.sh
launch attack_loop /tmp/aegis_attack_loop.sh

# ── 5. Public tunnel ──────────────────────────────────────────────
CLOUDFLARED_BIN="$(command -v cloudflared || true)"
if [ -z "$CLOUDFLARED_BIN" ] && [ -x "$HOME/.local/bin/cloudflared" ]; then
    CLOUDFLARED_BIN="$HOME/.local/bin/cloudflared"
fi

if [ -n "$CLOUDFLARED_BIN" ]; then
    launch tunnel "$CLOUDFLARED_BIN" tunnel --url "http://localhost:${OPS_PORT}"
    echo "[*] Waiting for tunnel URL..."
    TUNNEL_URL=""
    for i in $(seq 1 20); do
        TUNNEL_URL=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' /tmp/aegis_tunnel.log 2>/dev/null | head -1)
        [ -n "$TUNNEL_URL" ] && break
        sleep 1
    done
else
    echo "[!] cloudflared not found — skipping tunnel. Install it or use an SSH -L tunnel instead."
    TUNNEL_URL=""
fi

echo ""
echo "======================================================================"
if [ -n "$TUNNEL_URL" ]; then
    echo " Dashboard ready:  $TUNNEL_URL"
else
    echo " No tunnel URL yet — check manually:"
    echo "   grep trycloudflare.com /tmp/aegis_tunnel.log"
fi
echo ""
echo " Sandbox app (local):   http://localhost:${SANDBOX_PORT}"
echo " Ops dashboard (local): http://localhost:${OPS_PORT}"
echo ""
echo " Everything is fully detached — safe to keep using this terminal."
echo ""
echo " Logs:"
echo "   tail -f /tmp/aegis_sandbox.log"
echo "   tail -f /tmp/aegis_ops.log"
echo "   tail -f /tmp/aegis_attack.log"
echo "   tail -f /tmp/aegis_tunnel.log"
echo ""
echo " Check status:  ps -p \$(cat $PIDFILE | tr '\\n' ',' | sed 's/,\$//')"
echo " Stop everything:  ./scripts/stop_dashboard.sh"
echo "======================================================================"
