#!/usr/bin/env python
"""
Stress-test Aegis prompts against smaller LLMs.

Usage:
    # Test current env model
    python scripts/stress_test_prompts.py

    # Test specific models on Groq
    python scripts/stress_test_prompts.py --models gemma2-9b-it,llama3-8b-8192

    # Test with a different endpoint
    python scripts/stress_test_prompts.py --endpoint https://api.fireworks.ai/inference/v1 --api-key fw_...

Output: data/stress_test_results.json (gitignored)
"""

import json
import os
import sys
import time
import uuid
import argparse
from datetime import datetime, timezone
from pathlib import Path

_proj = Path(__file__).resolve().parents[1]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

from src.agents.contracts import (
    AlertEvent, LogEntry, ForensicReport, PatchProposal, Severity,
)
from src.agents.forensic_investigator import (
    investigate_llm, investigate, INVESTIGATOR_PATH_LLM, INVESTIGATOR_PATH_HEURISTIC,
)
from src.agents.patch_engineer import (
    _generate_patch_llm, generate_patch, validate_patch_syntax,
    PATCH_PATH_LLM, PATCH_PATH_LOOKUP,
)
from src.agents.config import LLMConfig

RESULTS_FILE = _proj / "data" / "stress_test_results.json"

SAMPLE_ALERTS = [
    AlertEvent(
        alert_id="stress-echo",
        created_at="2026-07-08T00:00:00Z",
        endpoint="/execute",
        payload="echo AEGIS_BREACH_OK",
        suspicious_indicators=["echo"],
        severity=Severity.HIGH,
        raw_logs=[LogEntry(timestamp="2026-07-08T00:00:00Z", source="sandbox_target",
                  raw_message="EXECUTE request: cmd='echo AEGIS_BREACH_OK'")],
    ),
    AlertEvent(
        alert_id="stress-chain",
        created_at="2026-07-08T00:00:00Z",
        endpoint="/execute",
        payload="dir src && whoami",
        suspicious_indicators=["dir", "whoami", "&&"],
        severity=Severity.HIGH,
        raw_logs=[LogEntry(timestamp="2026-07-08T00:00:00Z", source="sandbox_target",
                  raw_message="EXECUTE request: cmd='dir src && whoami'")],
    ),
    AlertEvent(
        alert_id="stress-read",
        created_at="2026-07-08T00:00:00Z",
        endpoint="/execute",
        payload="type C:\\Windows\\win.ini",
        suspicious_indicators=["type"],
        severity=Severity.HIGH,
        raw_logs=[LogEntry(timestamp="2026-07-08T00:00:00Z", source="sandbox_target",
                  raw_message="EXECUTE request: cmd='type C:\\Windows\\win.ini'")],
    ),
]

SAMPLE_REPORTS = [
    ForensicReport(
        report_id="rep-stress-1",
        alert_id="stress-echo",
        created_at="2026-07-08T00:00:00Z",
        file=str(_proj / "src" / "sandbox_target" / "app.py"),
        line=34,
        vuln_type="command_injection",
        severity=Severity.CRITICAL,
        vulnerable_code=(
            '        result = subprocess.run(\n'
            '            cmd,\n'
            '            shell=True,\n'
            '            capture_output=True,\n'
            '            text=True,\n'
            '            timeout=5,\n'
            '        )'
        ),
        attack_vector="Unsanitized user input passed to subprocess.run() with shell=True",
        stack_trace="EXECUTE request: cmd='echo AEGIS_BREACH_OK'",
        confidence=0.95,
    ),
    ForensicReport(
        report_id="rep-stress-2",
        alert_id="stress-chain",
        created_at="2026-07-08T00:00:00Z",
        file=str(_proj / "src" / "sandbox_target" / "app.py"),
        line=34,
        vuln_type="command_injection",
        severity=Severity.CRITICAL,
        vulnerable_code=(
            '        result = subprocess.run(\n'
            '            cmd,\n'
            '            shell=True,\n'
            '            capture_output=True,\n'
            '            text=True,\n'
            '            timeout=5,\n'
            '        )'
        ),
        attack_vector="Unsanitized user input passed to subprocess.run() with shell=True",
        stack_trace="EXECUTE request: cmd='dir src && whoami'",
        confidence=0.95,
    ),
]


def run_stress_test(models: list[str], num_runs: int, endpoint: str | None = None,
                    api_key: str | None = None) -> dict:
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "endpoint": endpoint or os.getenv("AEGIS_LLM_ENDPOINT", "default"),
        "num_runs_per_model": num_runs,
        "models": {},
    }

    for model in models:
        print(f"\n{'='*60}")
        print(f"Testing model: {model}")
        print(f"{'='*60}")

        model_results = {
            "investigator": {
                "total": 0, "llm_path": 0, "heuristic_path": 0,
                "low_confidence": 0, "parse_failures": 0, "rate_limited": 0,
                "wrong_line": 0, "confidences": [], "lines": [], "latencies_ms": [],
            },
            "patch_engineer": {
                "total": 0, "llm_path": 0, "lookup_path": 0,
                "parse_failures": 0, "syntax_failures": 0, "rate_limited": 0,
                "latencies_ms": [],
            },
            "errors": [],
        }

        config = LLMConfig()
        config.model = model
        if endpoint:
            config.endpoint = endpoint
        if api_key:
            config.api_key = api_key

        if not config.configured:
            model_results["errors"].append("API key not configured, skipping")
            results["models"][model] = model_results
            continue

        ts_start = time.time()

        # --- Investigator tests (using full investigate() pipeline) ---
        for run_idx in range(num_runs):
            alert = SAMPLE_ALERTS[run_idx % len(SAMPLE_ALERTS)]
            t0 = time.time()
            try:
                # Set env vars so config is picked up by investigate()
                os.environ["AEGIS_LLM_MODEL"] = model
                if endpoint:
                    os.environ["AEGIS_LLM_ENDPOINT"] = endpoint
                if api_key:
                    os.environ["AEGIS_LLM_API_KEY"] = api_key
                # Force re-read by creating fresh config each time
                report, inv_path = investigate(alert)
                latency = (time.time() - t0) * 1000
                model_results["investigator"]["latencies_ms"].append(round(latency, 1))
                model_results["investigator"]["total"] += 1
                model_results["investigator"]["confidences"].append(report.confidence)
                model_results["investigator"]["lines"].append(report.line)

                # Which path was used?
                if inv_path == INVESTIGATOR_PATH_LLM:
                    model_results["investigator"]["llm_path"] += 1
                else:
                    model_results["investigator"]["heuristic_path"] += 1

                if report.confidence < 0.7:
                    model_results["investigator"]["low_confidence"] += 1

                # Check if line is wrong (should be 34 for command injection)
                if report.line != 34:
                    model_results["investigator"]["wrong_line"] += 1

            except Exception as e:
                latency = (time.time() - t0) * 1000
                model_results["investigator"]["latencies_ms"].append(round(latency, 1))
                err_str = str(e)
                if "429" in err_str or "Too Many Requests" in err_str:
                    model_results["investigator"]["rate_limited"] += 1
                else:
                    model_results["investigator"]["parse_failures"] += 1
                model_results["errors"].append(
                    f"[inv][run {run_idx}] {type(e).__name__}: {e}"
                )

        # --- Patch Engineer tests (using full generate_patch()) ---
        for run_idx in range(num_runs):
            report = SAMPLE_REPORTS[run_idx % len(SAMPLE_REPORTS)]
            t0 = time.time()
            try:
                os.environ["AEGIS_LLM_MODEL"] = model
                if endpoint:
                    os.environ["AEGIS_LLM_ENDPOINT"] = endpoint
                if api_key:
                    os.environ["AEGIS_LLM_API_KEY"] = api_key
                patch_obj, patch_path = generate_patch(report)
                latency = (time.time() - t0) * 1000
                model_results["patch_engineer"]["latencies_ms"].append(round(latency, 1))
                model_results["patch_engineer"]["total"] += 1

                if patch_path == PATCH_PATH_LLM:
                    model_results["patch_engineer"]["llm_path"] += 1
                else:
                    model_results["patch_engineer"]["lookup_path"] += 1

                ok, _ = validate_patch_syntax(patch_obj.patch_code)
                if not ok:
                    model_results["patch_engineer"]["syntax_failures"] += 1
            except Exception as e:
                latency = (time.time() - t0) * 1000
                model_results["patch_engineer"]["latencies_ms"].append(round(latency, 1))
                err_str = str(e)
                if "429" in err_str or "Too Many Requests" in err_str:
                    model_results["patch_engineer"]["rate_limited"] += 1
                else:
                    model_results["patch_engineer"]["parse_failures"] += 1
                model_results["errors"].append(
                    f"[patch][run {run_idx}] {type(e).__name__}: {e}"
                )

        elapsed = time.time() - ts_start
        inv = model_results["investigator"]
        pat = model_results["patch_engineer"]
        print(f"\n  Investigator: {inv['total']} runs, "
              f"LLM={inv['llm_path']} heuristic={inv['heuristic_path']}, "
              f"{inv['low_confidence']} low-conf, "
              f"{inv['wrong_line']} wrong-line, "
              f"{inv['rate_limited']} rate-limited, "
              f"{inv['parse_failures']} other-errors")
        if inv["confidences"]:
            avg_c = sum(inv["confidences"]) / len(inv["confidences"])
            print(f"  Avg confidence: {avg_c:.3f}")
            print(f"  Lines reported: {inv['lines']}")
        if inv["latencies_ms"]:
            avg_l = sum(inv["latencies_ms"]) / len(inv["latencies_ms"])
            print(f"  Avg latency: {avg_l:.0f}ms")
        print(f"  PatchEngine: {pat['total']} runs, "
              f"LLM={pat['llm_path']} lookup={pat['lookup_path']}, "
              f"{pat['rate_limited']} rate-limited, "
              f"{pat['syntax_failures']} syntax fails, "
              f"{pat['parse_failures']} other-errors")
        print(f"  Elapsed: {elapsed:.1f}s")

        results["models"][model] = model_results

    # Save results
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nResults saved to {RESULTS_FILE}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Stress-test Aegis prompts against smaller LLMs")
    parser.add_argument("--models", default="gemma2-9b-it,llama3-8b-8192",
                        help="Comma-separated model names (default: gemma2-9b-it,llama3-8b-8192)")
    parser.add_argument("--runs", type=int, default=3,
                        help="Number of test runs per model (default: 3)")
    parser.add_argument("--endpoint", help="Override LLM endpoint")
    parser.add_argument("--api-key", help="Override LLM API key")
    args = parser.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    print("Aegis Prompt Stress Test")
    print(f"Models: {models}")
    print(f"Runs per model: {args.runs}")
    print(f"Endpoint: {args.endpoint or os.getenv('AEGIS_LLM_ENDPOINT', 'default')}")
    print()

    run_stress_test(models, args.runs, endpoint=args.endpoint, api_key=args.api_key)


if __name__ == "__main__":
    main()
