from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────

class VulnType(str, Enum):
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    XSS = "xss"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    AUTH_BYPASS = "auth_bypass"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ──────────────────────────────────────────────
# Agent 1 → Agent 2: AlertEvent (LogMonitor → Investigator)
# ──────────────────────────────────────────────

class LogEntry(BaseModel):
    timestamp: str
    source: str
    raw_message: str


class AlertEvent(BaseModel):
    alert_id: str = Field(description="Unique alert identifier")
    created_at: str = Field(description="ISO-8601 UTC timestamp")
    source_ip: str | None = None
    endpoint: str | None = None
    payload: str | None = None
    suspicious_indicators: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    raw_logs: list[LogEntry] = Field(default_factory=list)

    def model_dump_json(self, *args, **kwargs) -> str:
        return super().model_dump_json(*args, **kwargs)


# ──────────────────────────────────────────────
# Agent 2 → Agent 3: ForensicReport (Investigator → PatchEngine)
# ──────────────────────────────────────────────

class ForensicReport(BaseModel):
    report_id: str = Field(description="Unique report identifier")
    alert_id: str = Field(description="Reference to the originating AlertEvent")
    created_at: str = Field(description="ISO-8601 UTC timestamp")

    file: str = Field(description="Full path to the vulnerable source file")
    line: int = Field(description="Line number where the vulnerability resides")
    vuln_type: VulnType = Field(description="Classification of the vulnerability")
    severity: Severity = Severity.HIGH

    vulnerable_code: str = Field(description="The exact vulnerable code snippet")
    attack_vector: str = Field(description="How the attacker exploited this vulnerability")
    stack_trace: str = Field(description="Relevant stack trace lines")

    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence score (0.0–1.0) that this is the true root cause",
    )


# ──────────────────────────────────────────────
# Agent 3 output: PatchProposal (PatchEngine → filesystem deploy)
# ──────────────────────────────────────────────

class PatchProposal(BaseModel):
    patch_id: str = Field(description="Unique patch identifier")
    report_id: str = Field(description="Reference to the originating ForensicReport")
    created_at: str = Field(description="ISO-8601 UTC timestamp")

    target_file: str = Field(description="Absolute path of the file to patch")
    target_line: int = Field(description="Line number where the patch is applied")
    vuln_type: VulnType = Field(description="Vulnerability being patched")

    original_code: str = Field(description="The original vulnerable code (for verification)")
    patch_code: str = Field(
        description="The replacement secure code block. "
                    "MUST be valid source code only — no markdown, no backticks, no commentary."
    )

    rationale: str = Field(
        description="One-paragraph explanation of why the patch fixes the vulnerability"
    )


# ──────────────────────────────────────────────
# Agent system prompts (enforce structured output)
# ──────────────────────────────────────────────

LOG_MONITOR_PROMPT = """\
You are Aegis LogMonitor, a cybersecurity surveillance AI.
Your job is to analyze raw network traffic and system logs for signs of intrusion.

Rules:
- Read the input log lines carefully.
- If you detect suspicious activity, output a valid JSON object matching the AlertEvent schema.
- If no threat is detected, output: {"alert": null}
- Output ONLY raw JSON. No markdown, no backticks, no explanation, no commentary.
- Do not wrap the JSON in code fences. The raw JSON must be parseable by `json.loads()`.
"""

FORENSIC_INVESTIGATOR_PROMPT = """\
You are Aegis ForensicInvestigator, a digital forensic analyst.
Your job is to trace an attack back to its root cause in the source code.

You receive: an alert ID, source file path, raw logs, a suspicious payload, and the full source file.
The vulnerability is a line in the source code that accepts untrusted input
and passes it directly to a dangerous function (e.g., subprocess.run with shell=True,
eval(), exec(), os.system(), SQL string concatenation).
Do NOT report error-handling lines, logging lines, or data-formatting lines as vulnerabilities.

You must produce: raw JSON matching the ForensicReport schema below.

Required JSON fields (ALL mandatory):
  "report_id":       str — 12-char hex, e.g. "a1b2c3d4e5f6"
  "alert_id":        str — copy exactly from the input Alert ID line above
  "created_at":      str — ISO-8601 UTC, e.g. "2026-07-08T00:00:00Z"
  "file":            str — full absolute path (copy from the input path line)
  "line":            int — exact 1-based line number in the source file
  "vuln_type":       str — one of: "command_injection", "sql_injection",
                           "path_traversal", "buffer_overflow", "xss",
                           "ssrf", "deserialization", "auth_bypass", "unknown"
  "severity":        str — one of: "critical", "high", "medium", "low", "info"
  "vulnerable_code": str — the EXACT vulnerable lines from the source,
                           preserving all indentation and newlines
  "attack_vector":   str — description of how the attacker exploited this
  "stack_trace":     str — the raw log lines provided above
  "confidence":      float — 0.0–1.0. Use the full range, do not default to 0.9:
      0.95–1.0 if the source code explicitly has an unsafe call (shell=True, eval, etc.)
              at a line that handles user-controlled input
      0.80–0.94 if evidence strongly implies a specific location but lacks direct proof
      0.60–0.79 if plausible but unconfirmed
      0.50–0.59 if you are guessing based on weak signals
      below 0.5 if uncertain

Rules:
- Output ONLY raw JSON. No markdown, no backticks, no explanation, no extra text.
- The "file" field must be the EXACT path given in the prompt, not a made-up path.
- The "line" field must match the actual line in the source file provided.
- "vulnerable_code" must be the exact characters from the source file at the reported line.
- Every field above must be present. Missing fields will cause rejection.
- Example valid output (do NOT copy this report_id — generate your own):
  {"report_id": "abc123def456", "alert_id": "alert-001", "created_at": "2026-07-08T00:00:00Z", "file": "/path/to/app.py", "line": 34, "vuln_type": "command_injection", "severity": "critical", "vulnerable_code": "result = subprocess.run(\\ncmd,\\nshell=True,\\n", "attack_vector": "description", "stack_trace": "logs", "confidence": 0.95}
"""

PATCH_ENGINEER_PROMPT = """\
You are Aegis PatchEngineer, an automated code security fixer.
Your job is to write a secure replacement for vulnerable code.

You receive: a ForensicReport with file path, line number, vulnerable code.
You must produce: raw JSON matching the PatchProposal schema below.

Required JSON fields (ALL mandatory):
  "patch_id":      str — 12-char hex, e.g. "f1e2d3c4b5a6"
  "report_id":     str — copy exactly from the input Report ID line
  "created_at":    str — ISO-8601 UTC, e.g. "2026-07-08T00:00:00Z"
  "target_file":   str — absolute path (copy from the input path line)
  "target_line":   int — line number (copy from the input line)
  "vuln_type":     str — one of: "command_injection", "sql_injection",
                          "path_traversal", "buffer_overflow", "xss",
                          "ssrf", "deserialization", "auth_bypass", "unknown"
  "original_code":  str — copy the EXACT vulnerable code with indentation from the input
  "patch_code":    str — ONLY valid Python source code, preserving the SAME
                          indentation level as the original. No markdown, no backticks.
  "rationale":     str — one-paragraph explanation of why the fix works

Rules:
- Output ONLY raw JSON. No markdown, no backticks, no explanation, no extra text.
- The patch_code must be valid Python (test mentally). Use the same indentation as the original.
- target_file, target_line, vuln_type must match the input exactly.
- original_code must be an exact copy of the vulnerable code block from the input.
- Every field above must be present. Missing fields will cause rejection.
- Example valid output (do NOT copy this patch_id — generate your own):
  {"patch_id": "fedcba654321", "report_id": "abc123def456", "created_at": "2026-07-08T00:00:00Z", "target_file": "/path/to/app.py", "target_line": 34, "vuln_type": "command_injection", "original_code": "result = subprocess.run(\\ncmd,\\nshell=True,\\n", "patch_code": "result = subprocess.run(\\nshlex.split(cmd),\\ncapture_output=True,\\ntext=True,\\ntimeout=5,\\n)", "rationale": "Replaced shell=True with shlex.split() to prevent shell injection."}
"""


# ──────────────────────────────────────────────
# Serialization helpers
# ──────────────────────────────────────────────

def serialize(obj: BaseModel) -> str:
    return obj.model_dump_json()


def deserialize(model_cls: type[BaseModel], raw: str) -> BaseModel:
    return model_cls.model_validate(json.loads(raw))
