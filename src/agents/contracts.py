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

You receive: an AlertEvent JSON object.
You must produce: a ForensicReport JSON object.

Calibrate your confidence field as follows:
  - 0.9+ if logs or stack trace explicitly name the file and line number
  - 0.7–0.89 if the evidence strongly implies a specific location
  - 0.5–0.69 if the inference is plausible but unconfirmed
  - below 0.5 if uncertain

Rules:
- Identify the exact file path and line number of the vulnerable code.
- Output ONLY raw JSON matching the ForensicReport schema.
- No markdown, no backticks, no explanation, no commentary.
- The output must be parseable by `json.loads()`.
"""

PATCH_ENGINEER_PROMPT = """\
You are Aegis PatchEngineer, an automated code security fixer.
Your job is to write a secure replacement for vulnerable code.

You receive: a ForensicReport JSON object.
You must produce: a PatchProposal JSON object.

Rules:
- Output ONLY raw JSON matching the PatchProposal schema.
- The patch_code field must contain ONLY valid source code — no markdown, no backticks, no commentary.
- Do not wrap anything in code fences.
- The output must be parseable by `json.loads()`.
- Ensure the patch fixes the vulnerability without breaking existing functionality.
"""


# ──────────────────────────────────────────────
# Serialization helpers
# ──────────────────────────────────────────────

def serialize(obj: BaseModel) -> str:
    return obj.model_dump_json()


def deserialize(model_cls: type[BaseModel], raw: str) -> BaseModel:
    return model_cls.model_validate(json.loads(raw))
