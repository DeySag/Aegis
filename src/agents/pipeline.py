import ast
import copy
import json
import sys
import time
import traceback
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
) -> tuple[PatchProposal | None, list[str]]:
    logs: list[str] = []
    attempt = 0
    patch = None

    while attempt <= max_retries:
        if attempt > 0:
            logs.append(f"[Retry {attempt}/{max_retries}] Regenerating patch...")
            # Re-seed the report for a fresh generation
            report_copy = copy.deepcopy(report)
            if isinstance(report_copy, ForensicReport):
                report_copy.vulnerable_code += (
                    f"\n# Previous attempt failed syntax check."
                )

        patch = generate_patch(report)
        ok, error_msg = validate_patch_syntax(patch.patch_code)

        if ok:
            logs.append(f"[PatchEngine] Syntax valid on attempt {attempt + 1}")
            return patch, logs

        logs.append(
            f"[PatchEngine] Syntax error on attempt {attempt + 1}: {error_msg}"
        )

        if attempt < max_retries:
            # Modify the report to include error feedback
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
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "alert_id": None,
        "report": None,
        "patch": None,
        "retry_logs": [],
        "applied": False,
        "test_passed": False,
        "errors": [],
    }

    try:
        report = investigate(alert)
        result["alert_id"] = report.alert_id
        result["report"] = json.loads(serialize(report))
        print(f"[Pipeline] Investigator -> report {report.report_id} "
              f"(file={report.file}:{report.line}, conf={report.confidence})")
    except Exception as e:
        result["errors"].append(f"Investigator failed: {e}")
        return result

    try:
        patch, retry_logs = generate_patch_with_retry(report)
        result["retry_logs"] = retry_logs
        for log in retry_logs:
            print(f"  {log}")

        if patch is None:
            result["errors"].append("Patch generation failed after retries")
            return result

        result["patch"] = json.loads(serialize(patch))
        print(f"[Pipeline] PatchEngine -> patch {patch.patch_id}")
    except Exception as e:
        result["errors"].append(f"Patch generation failed: {e}")
        return result

    if apply:
        try:
            applied_path = apply_patch(patch)
            result["applied"] = True
            trigger_hot_reload(applied_path)
            print(f"[Pipeline] Patch applied -> {applied_path}")
        except Exception as e:
            result["errors"].append(f"Patch application failed: {e}")
            return result

    if test and result["applied"]:
        try:
            test_result = run_sandbox_test()
            result["test_passed"] = test_result.get("passed", False)
            print(f"[Pipeline] Sandbox test: {'PASSED' if result['test_passed'] else 'FAILED'}")
            if not result["test_passed"]:
                result["errors"].append(f"Sandbox test failed: {test_result.get('details', 'unknown')}")
        except Exception as e:
            result["errors"].append(f"Sandbox test errored: {e}")
            result["test_passed"] = False

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
