import ast
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_proj = Path(__file__).resolve().parents[2]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

from src.agents.contracts import ForensicReport, PatchProposal, VulnType


SECURE_REPLACEMENTS: dict[str, str] = {
    VulnType.COMMAND_INJECTION: (
        "result = subprocess.run(\n"
        "            shlex.split(cmd),\n"
        "            capture_output=True,\n"
        "            text=True,\n"
        "            timeout=5,\n"
        "        )"
    ),
}

FIX_IMPORTS: dict[str, list[str]] = {
    VulnType.COMMAND_INJECTION: ["import shlex"],
}


def generate_patch(report: ForensicReport | dict) -> PatchProposal:
    if isinstance(report, dict):
        report = ForensicReport.model_validate(report)

    vuln_key = report.vuln_type
    patch_code = SECURE_REPLACEMENTS.get(vuln_key)
    if not patch_code:
        patch_code = (
            f"# FIXME: No predefined patch for {vuln_key.value}\n"
            f"# Original: {report.vulnerable_code.strip()}"
        )

    original_snippet = report.vulnerable_code.strip()

    return PatchProposal(
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
    orig_code = patch.original_code.strip()
    patch_code = patch.patch_code.strip()

    if orig_code in content:
        content = content.replace(orig_code, patch_code, 1)
    else:
        # fallback: line-based replacement
        lines = content.splitlines()
        line_idx = patch.target_line - 1
        if 0 <= line_idx < len(lines):
            lines[line_idx] = f"# PATCHED: {lines[line_idx]}"
            patch_lines = patch_code.split("\n")
            lines[line_idx:line_idx + 1] = [""] + patch_lines
        content = "\n".join(lines)

    target.write_text(content, encoding="utf-8")

    # Add necessary imports if missing
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
        ast.parse(patch_code)
        return True, None
    except SyntaxError as e:
        return False, str(e)


if __name__ == "__main__":
    from src.agents.contracts import LogEntry

    sample = ForensicReport(
        report_id="rep-001",
        alert_id="alert-001",
        created_at="2026-07-08T00:00:00Z",
        file=str(_proj / "src" / "sandbox_target" / "app.py"),
        line=34,
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

    patch = generate_patch(sample)
    print("=== Patch Proposal ===")
    print(patch.model_dump_json(indent=2))
    ok, err = validate_patch_syntax(patch.patch_code)
    print(f"\nSyntax valid: {ok}")
    if err:
        print(f"Error: {err}")
