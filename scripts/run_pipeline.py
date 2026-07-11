"""
Run the Aegis investigate -> patch -> apply -> test pipeline from the CLI.

Usage:
    python scripts/run_pipeline.py --vuln command_injection
    python scripts/run_pipeline.py --vuln sql_injection --payload "nonexistent' OR '1'='1' --"
    python scripts/run_pipeline.py --vuln ssrf --no-apply --no-test   # dry run: investigate + patch only
    python scripts/run_pipeline.py --vuln deserialization             # builds a real pickle payload for you
"""

import argparse
import base64
import json
import os
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.contracts import AlertEvent, LogEntry, Severity
from src.agents.pipeline import run_pipeline


# endpoint, param-name-in-log, default payload, log-line-prefix per vuln type
DEFAULTS = {
    "command_injection": ("/execute", "cmd", "dir src && whoami", "EXECUTE"),
    "sql_injection": ("/search", "name", "nonexistent' OR '1'='1' --", "SEARCH"),
    "path_traversal": ("/download", "file", "../app.py", "DOWNLOAD"),
    "ssrf": ("/webhook", "url", "http://localhost:8000/ping", "WEBHOOK"),
    # deserialization payload is built dynamically below (needs real pickle bytes)
    "deserialization": ("/session", "token", None, "SESSION"),
}


def build_deserialization_payload() -> str:
    class _EchoMarker:
        def __reduce__(self):
            return (os.system, ("echo AEGIS_TEST_HARNESS",))
    return base64.b64encode(pickle.dumps(_EchoMarker())).decode()


def main():
    parser = argparse.ArgumentParser(description="Run the Aegis pipeline once against a chosen vuln type.")
    parser.add_argument("--vuln", "-v", required=True, choices=list(DEFAULTS.keys()),
                         help="Which vulnerability class to simulate an alert for.")
    parser.add_argument("--payload", "-p", default=None,
                         help="Override the default exploit payload for this vuln type.")
    parser.add_argument("--no-apply", action="store_true",
                         help="Don't write the patch to disk (investigate + generate patch only).")
    parser.add_argument("--no-test", action="store_true",
                         help="Don't re-attack the patched sandbox to verify the fix.")
    args = parser.parse_args()

    endpoint, param, default_payload, prefix = DEFAULTS[args.vuln]
    payload = args.payload or default_payload or build_deserialization_payload()

    now = datetime.now(timezone.utc).isoformat()
    alert = AlertEvent(
        alert_id=f"cli-{args.vuln}",
        created_at=now,
        endpoint=endpoint,
        payload=payload,
        suspicious_indicators=["cli-triggered"],
        severity=Severity.HIGH,
        raw_logs=[LogEntry(
            timestamp=now,
            source="sandbox_target",
            raw_message=f"{prefix} request: {param}='{payload}'",
        )],
    )

    print(f"[*] vuln={args.vuln}  endpoint={endpoint}  payload={payload[:80]!r}")
    print(f"[*] apply={not args.no_apply}  test={not args.no_test}\n")

    out = run_pipeline(alert, apply=not args.no_apply, test=not args.no_test)

    print("\n--- Result ---")
    print("investigator_path:", out["investigator_path"])
    print("patch_path:       ", out["patch_path"])
    print("applied:          ", out["applied"])
    print("test_passed:      ", out["test_passed"])
    print("errors:           ", out["errors"])

    if out.get("report"):
        print("\nvuln_type (confirmed):", out["report"].get("vuln_type"))
        print("confidence:           ", out["report"].get("confidence"))

    print(json.dumps({k: v for k, v in out.items() if k not in ("report", "patch")}, indent=2, default=str))


if __name__ == "__main__":
    main()
