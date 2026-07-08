import ast
import copy
import json
import sys
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

_proj = Path(__file__).resolve().parents[2]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

from src.agents.contracts import (
    AlertEvent,
    ForensicReport,
    PatchProposal,
    serialize,
)
from src.agents.forensic_investigator import investigate
from src.agents.patch_engineer import (
    FIX_IMPORTS,
    SECURE_REPLACEMENTS,
    apply_patch,
    generate_patch,
    trigger_hot_reload,
    validate_patch_syntax,
)
from src.sandbox_target.harness import run_sandbox_test

MAX_RETRIES = 2


def generate_patch_with_retry(
    report: ForensicReport | dict,
    max_retries: int = MAX_RETRIES,
    on_event: Callable[[str, dict], None] | None = None,
) -> tuple[PatchProposal | None, list[str]]:
    from src.agents.patch_engineer import PATCH_PATH_LLM, PATCH_PATH_LOOKUP

    logs: list[str] = []
    attempt = 0
    patch = None

    while attempt <= max_retries:
        if attempt > 0:
            logs.append(f"[Retry {attempt}/{max_retries}] Regenerating patch...")
            report_copy = copy.deepcopy(report)
            if isinstance(report_copy, ForensicReport):
                report_copy.vulnerable_code += (
                    f"\n# Previous attempt failed syntax check."
                )

        patch_obj, patch_path = generate_patch(report, on_event=on_event)
        logs.append(f"[PatchEngine] Path: {patch_path}")
        patch = patch_obj
        ok, error_msg = validate_patch_syntax(patch.patch_code)

        if ok:
            logs.append(f"[PatchEngine] Syntax valid on attempt {attempt + 1}")
            return patch, logs

        logs.append(
            f"[PatchEngine] Syntax error on attempt {attempt + 1}: {error_msg}"
        )

        if attempt < max_retries:
            if isinstance(report, dict):
                report["vulnerable_code"] = (
                    report.get("vulnerable_code", "") +
                    f"\n# SYNTAX ERROR FEEDBACK: {error_msg}"
                )
            else:
                report.vulnerable_code += (
                    f"\n# SYNTAX ERROR FEEDBACK: {error_msg}"
                )

        attempt += 1

    logs.append("[PatchEngine] All retries exhausted — patch validation failed.")
    return None, logs


def run_pipeline(
    alert: AlertEvent | dict,
    apply: bool = True,
    test: bool = True,
    on_event: Callable[[str, dict], None] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "alert_id": None,
        "report": None,
        "patch": None,
        "retry_logs": [],
        "applied": False,
        "test_passed": False,
        "investigator_path": None,
        "patch_path": None,
        "errors": [],
    }

    pipeline_start = time.time()

    try:
        alert_id = alert.alert_id if isinstance(alert, AlertEvent) else alert.get("alert_id")
        payload = alert.payload if isinstance(alert, AlertEvent) else alert.get("payload", "")
        severity = alert.severity.value if isinstance(alert, AlertEvent) else alert.get("severity", "high")
        indicators = alert.suspicious_indicators if isinstance(alert, AlertEvent) else alert.get("suspicious_indicators", [])
    except Exception:
        alert_id = "unknown"
        payload = ""
        severity = "high"
        indicators = []

    if on_event:
        on_event("alert", {
            "alert_id": alert_id,
            "payload": payload,
            "severity": severity,
            "indicators": indicators,
        })

    try:
        report, inv_path = investigate(alert, on_event=on_event)
        result["alert_id"] = report.alert_id
        result["report"] = json.loads(serialize(report))
        result["investigator_path"] = inv_path
        print(f"[Pipeline] Investigator -> report {report.report_id} "
              f"(file={report.file}:{report.line}, conf={report.confidence}, "
              f"path={inv_path})")
        if on_event:
            on_event("investigate", {
                "path": inv_path,
                "file": report.file,
                "line": report.line,
                "confidence": report.confidence,
                "vuln_type": report.vuln_type.value,
                "severity": report.severity.value if hasattr(report.severity, 'value') else str(report.severity),
            })
    except Exception as e:
        result["errors"].append(f"Investigator failed: {e}")
        if on_event:
            on_event("error", {"message": f"Investigation failed: {e}", "stage": "investigate"})
        return result

    try:
        patch, retry_logs = generate_patch_with_retry(report, on_event=on_event)
        result["retry_logs"] = retry_logs
        for log in retry_logs:
            print(f"  {log}")

        if patch is None:
            msg = "Patch generation failed after retries"
            result["errors"].append(msg)
            if on_event:
                on_event("error", {"message": msg, "stage": "patch"})
            return result

        result["patch"] = json.loads(serialize(patch))
        patch_path = next((l.split("Path: ")[-1] for l in retry_logs if "Path: " in l), "unknown")
        result["patch_path"] = patch_path
        print(f"[Pipeline] PatchEngine -> patch {patch.patch_id} (path={patch_path})")
        if on_event:
            on_event("patch", {
                "path": patch_path,
                "patch_id": patch.patch_id,
                "vuln_type": patch.vuln_type.value,
                "target_file": patch.target_file,
                "target_line": patch.target_line,
            })
    except Exception as e:
        result["errors"].append(f"Patch generation failed: {e}")
        if on_event:
            on_event("error", {"message": f"Patch generation failed: {e}", "stage": "patch"})
        return result

    if apply:
        try:
            applied_path = apply_patch(patch)
            result["applied"] = True
            trigger_hot_reload(applied_path)
            print(f"[Pipeline] Patch applied -> {applied_path}")
            if on_event:
                on_event("apply", {"file": applied_path})
        except Exception as e:
            result["errors"].append(f"Patch application failed: {e}")
            if on_event:
                on_event("error", {"message": f"Patch application failed: {e}", "stage": "apply"})
            return result

    if test and result["applied"]:
        try:
            test_result = run_sandbox_test()
            result["test_passed"] = test_result.get("passed", False)
            print(f"[Pipeline] Sandbox test: {'PASSED' if result['test_passed'] else 'FAILED'}")
            if on_event:
                on_event("validate", {
                    "passed": result["test_passed"],
                    "startup_failed": test_result.get("startup_failed", False),
                    "exploit_count": test_result.get("exploitable_count", 0),
                })
            if not result["test_passed"]:
                result["errors"].append(f"Sandbox test failed: {test_result.get('details', 'unknown')}")
        except Exception as e:
            result["errors"].append(f"Sandbox test errored: {e}")
            result["test_passed"] = False
            if on_event:
                on_event("error", {"message": f"Sandbox test errored: {e}", "stage": "validate"})

    if on_event:
        elapsed = round(time.time() - pipeline_start, 2)
        on_event("resolve", {
            "passed": result.get("test_passed", False) if test else True,
            "investigator_path": result.get("investigator_path"),
            "patch_path": result.get("patch_path"),
            "applied": result.get("applied", False),
            "total_time_s": elapsed,
            "errors": result.get("errors", []),
        })

    return result


if __name__ == "__main__":
    from src.agents.contracts import LogEntry

    sample = AlertEvent(
        alert_id="pipe-test",
        created_at="2026-07-08T00:00:00Z",
        endpoint="/execute",
        payload="dir src && whoami",
        suspicious_indicators=["dir", "whoami", "&&"],
        severity="high",
        raw_logs=[
            LogEntry(
                timestamp="2026-07-08T00:00:00Z",
                source="sandbox_target",
                raw_message="EXECUTE request: cmd='dir src && whoami'",
            )
        ],
    )
    out = run_pipeline(sample, apply=False, test=False)
    print("\n=== Pipeline Result ===")
    print(json.dumps(out, indent=2, default=str))
