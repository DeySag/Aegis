import ast
import json
import os
import shutil
import sys
import textwrap
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_proj = Path(__file__).resolve().parents[2]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

from src.agents.config import LLMConfig
from src.agents.contracts import (
    ForensicReport,
    PatchProposal,
    PATCH_ENGINEER_PROMPT,
    VulnType,
)
from src.agents.llm_client import chat, extract_json

SECURE_REPLACEMENTS: dict[str, str] = {
    VulnType.COMMAND_INJECTION: (
        "        result = subprocess.run(\n"
        "            shlex.split(cmd),\n"
        "            capture_output=True,\n"
        "            text=True,\n"
        "            timeout=5,\n"
        "        )"
    ),
    VulnType.SQL_INJECTION: (
        "        cur.execute(\n"
        "            \"SELECT id, name, role FROM users WHERE name = ?\",\n"
        "            (name,),\n"
        "        )"
    ),
    VulnType.PATH_TRAVERSAL: (
        "        target = (REPORTS_DIR / file).resolve()\n"
        "        if REPORTS_DIR.resolve() not in target.parents and target != REPORTS_DIR.resolve():\n"
        "            raise ValueError(\"path escapes REPORTS_DIR\")"
    ),
    VulnType.DESERIALIZATION: (
        "        obj = json.loads(raw.decode(\"utf-8\"))"
    ),
    VulnType.SSRF: (
        "        parsed = urlparse(url)\n"
        "        if parsed.hostname not in ALLOWED_WEBHOOK_HOSTS:\n"
        "            raise ValueError(\"host not in webhook allowlist\")\n"
        "        resp = requests.get(url, timeout=3)"
    ),
}

FIX_IMPORTS: dict[str, list[str]] = {
    VulnType.COMMAND_INJECTION: ["import shlex"],
    VulnType.SQL_INJECTION: [],
    VulnType.PATH_TRAVERSAL: [],
    VulnType.DESERIALIZATION: ["import json"],
    VulnType.SSRF: ["from urllib.parse import urlparse"],
}
# Note: the SSRF fallback patch references ALLOWED_WEBHOOK_HOSTS, which is
# already defined as a module-level constant in sandbox_target/app.py.


def _generate_patch_llm(report: ForensicReport, max_retries: int = 2,
                        config_override: LLMConfig | None = None) -> PatchProposal | None:
    config = config_override or LLMConfig()
    if not config.configured:
        return None

    allowed_vuln_types = [
        "command_injection", "sql_injection", "path_traversal",
        "buffer_overflow", "xss", "ssrf", "deserialization",
        "auth_bypass", "unknown",
    ]

    vuln_code = report.vulnerable_code
    last_error: str | None = None

    for attempt in range(max_retries + 1):
        error_hint = ""
        if last_error:
            error_hint = (
                f"\n\nPrevious attempt's syntax error: {last_error}\n"
                f"Fix the indentation and ensure the code is valid Python."
            )

        user_prompt = (
            f"Report ID (copy this into your output's report_id field): {report.report_id}\n\n"
            f"Vulnerable file: {report.file}:{report.line}\n\n"
            f"vuln_type must be exactly one of: {allowed_vuln_types}\n"
            f"(the input report has vuln_type={report.vuln_type.value})\n\n"
            f"Vulnerable code (use the SAME indentation in your patch):\n"
            f"```python\n{vuln_code}\n```\n\n"
            f"Attack vector: {report.attack_vector}\n\n"
            f"IMPORTANT: Do NOT include import statements in patch_code. "
            f"Imports are handled separately. Output ONLY the replacement code "
            f"at the exact same indentation level as the original.\n\n"
            f"Output ONLY a raw JSON object matching the PatchProposal schema. "
            f"No markdown, no backticks, no commentary."
            f"{error_hint}"
        )

        try:
            raw = chat(PATCH_ENGINEER_PROMPT, user_prompt, config)
            cleaned = extract_json(raw)
            data = json.loads(cleaned)
            # Inject the actual file/line/vuln_type from the report to avoid copy errors
            data.setdefault("target_file", report.file)
            data.setdefault("target_line", report.line)
            data.setdefault("vuln_type", report.vuln_type.value)
            patch = PatchProposal.model_validate(data)

            ok, err = validate_patch_syntax(patch.patch_code)
            if ok:
                print(f"[PatchEngine] LLM patch valid on attempt {attempt + 1}")
                return patch
            else:
                last_error = err
                print(f"[PatchEngine] LLM patch syntax error (attempt {attempt + 1}): {err}")
        except Exception as e:
            last_error = str(e)
            print(f"[PatchEngine] LLM path attempt {attempt + 1} failed ({e})")

    return None


PATCH_PATH_LLM = "llm"
PATCH_PATH_LOOKUP = "lookup"


def generate_patch(report: ForensicReport | dict,
                   on_event: Callable[[str, dict], None] | None = None) -> tuple[PatchProposal, str]:
    if isinstance(report, dict):
        report = ForensicReport.model_validate(report)

    llm_patch = _generate_patch_llm(report)
    if llm_patch is not None:
        print(f"[PatchEngine] Path: LLM")
        return llm_patch, PATCH_PATH_LLM

    if on_event:
        on_event("fallback", {
            "path": "lookup",
            "vuln_type": report.vuln_type.value,
            "reason": "llm_all_retries_exhausted",
        })

    print("[PatchEngine] Path: lookup fallback")
    vuln_key = report.vuln_type
    patch_code = SECURE_REPLACEMENTS.get(vuln_key)
    if not patch_code:
        patch_code = (
            f"# FIXME: No predefined patch for {vuln_key.value}\n"
            f"# Original: {report.vulnerable_code.strip()}"
        )

    original_snippet = report.vulnerable_code.strip()

    return (
        PatchProposal(
            patch_id=uuid.uuid4().hex[:12],
            report_id=report.report_id,
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            target_file=report.file,
            target_line=report.line,
            vuln_type=report.vuln_type,
            original_code=original_snippet,
            patch_code=patch_code,
            rationale=(
                f"Replaced unsafe shell=True invocation with safe "
                f"shlex.split() based call to prevent command injection."
            ),
        ),
        PATCH_PATH_LOOKUP,
    )


def apply_patch(patch: PatchProposal | dict, backup: bool = True) -> str:
    if isinstance(patch, dict):
        patch = PatchProposal.model_validate(patch)

    target = Path(patch.target_file)
    if not target.exists():
        raise FileNotFoundError(f"Target file not found: {target}")

    if backup:
        backup_path = target.with_suffix(".py.bak")
        shutil.copy2(str(target), str(backup_path))
        print(f"[PatchEngine] Backup saved: {backup_path}")

    content = target.read_text(encoding="utf-8")

    lines = content.splitlines()
    line_idx = patch.target_line - 1
    if 0 <= line_idx < len(lines):
        target_indent = len(lines[line_idx]) - len(lines[line_idx].lstrip())
        # Track paren depth from target line to find end of original block.
        # Handles both single-line (depth=0 at target line) and multi-line
        # (e.g. subprocess.run( ... )) blocks.
        depth = 0
        end_idx = line_idx
        for i in range(line_idx, len(lines)):
            s = lines[i].strip()
            depth += s.count("(") - s.count(")")
            if depth <= 0:
                end_idx = i
                break
        # Remove the original block (target line through closing paren)
        del lines[line_idx:end_idx + 1]
        # Normalize patch indentation: dedent to 0, then re-indent to match target
        raw = patch.patch_code
        dedented = textwrap.dedent(raw).rstrip()
        if dedented:
            indented = textwrap.indent(dedented, " " * target_indent)
            patch_lines = [""] + indented.split("\n")
            for j, pl in enumerate(patch_lines):
                lines.insert(line_idx + j, pl)
    content = "\n".join(lines)

    target.write_text(content, encoding="utf-8")

    extra_imports = FIX_IMPORTS.get(patch.vuln_type, [])
    if extra_imports:
        content = target.read_text(encoding="utf-8")
        for imp in extra_imports:
            if imp not in content:
                content = imp + "\n" + content
        target.write_text(content, encoding="utf-8")

    print(f"[PatchEngine] Patch applied to {target}:{patch.target_line}")
    return str(target)


def trigger_hot_reload(target_file: str):
    os_name = sys.platform
    path = Path(target_file)
    if os_name == "win32":
        path.touch()
    else:
        os.utime(path, None)
    print(f"[PatchEngine] Touched {path} to trigger reload")


def validate_patch_syntax(patch_code: str) -> tuple[bool, str | None]:
    try:
        # Dedent so indented replacement code still parses standalone
        dedented = textwrap.dedent(patch_code)
        ast.parse(dedented)
        return True, None
    except SyntaxError as e:
        return False, str(e)


if __name__ == "__main__":
    sample = ForensicReport(
        report_id="rep-001",
        alert_id="alert-001",
        created_at="2026-07-08T00:00:00Z",
        file=str(_proj / "src" / "sandbox_target" / "app.py"),
        line=68,
        vuln_type=VulnType.COMMAND_INJECTION,
        severity="critical",
        vulnerable_code=(
            '        result = subprocess.run(\n'
            '            cmd,\n'
            '            shell=True,\n'
            '            capture_output=True,\n'
            '            text=True,\n'
            '            timeout=5,\n'
            '        )'
        ),
        attack_vector="test",
        stack_trace="test",
        confidence=0.95,
    )

    patch, path = generate_patch(sample)
    print(f"Path: {path}")
    print("=== Patch Proposal ===")
    print(patch.model_dump_json(indent=2))
    ok, err = validate_patch_syntax(patch.patch_code)
    print(f"\nSyntax valid: {ok}")
    if err:
        print(f"Error: {err}")
