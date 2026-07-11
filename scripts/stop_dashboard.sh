#!/usr/bin/env bash
# Stops everything started by start_dashboard.sh.
PIDFILE=/tmp/aegis_pids.txt

if [ ! -f "$PIDFILE" ]; then
    echo "[!] No $PIDFILE found — nothing tracked. Falling back to pattern match."
    pkill -f "uvicorn src.sandbox_target.app" 2>/dev/null
    pkill -f "uvicorn src.agents.ops_server" 2>/dev/null
    pkill -f "aegis_attack_loop.sh" 2>/dev/null
    pkill -f "cloudflared tunnel" 2>/dev/null
    echo "[*] Done (pattern-based cleanup)."
    exit 0
fi

while read -r pid; do
    [ -z "$pid" ] && continue
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        echo "[*] Stopped pid $pid"
    fi
done < "$PIDFILE"

# also sweep the attack loop's own child python process, since the loop
# script's pid isn't the python process itself
pkill -f "scripts/attack.py" 2>/dev/null

> "$PIDFILE"
echo "[*] Done."
