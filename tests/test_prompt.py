import sys
sys.path.insert(0, "src")

from src.agents.forensic_investigator import investigate_llm
from src.agents.contracts import AlertEvent, LogEntry, Severity
from datetime import datetime, timezone

payloads = [
    ("echo KAVACH_BREACH_OK", "medium"),
    ("type C:\\Windows\\win.ini", "medium"),
    ("echo start && dir && echo end", "high"),
    ("ping -n 1 127.0.0.1", "medium"),
    ("dir /s /b src\\sandbox_target", "critical"),
]

for payload, sev in payloads:
    alert = AlertEvent(
        alert_id=f"test-{payload[:8]}",
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        endpoint="/execute",
        payload=payload,
        suspicious_indicators=payload.split(),
        severity=sev,
        raw_logs=[LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            source="sandbox_target",
            raw_message=f"EXECUTE request: cmd='{payload}'",
        )],
    )
    result = investigate_llm(alert)
    if result:
        status = "PASS" if result.line == 34 else f"FAIL(line={result.line})"
        print(f"[{status}] {payload[:44]:44s} line={result.line} conf={result.confidence}")
    else:
        print(f"[SKIP]  {payload[:44]:44s} None (rejected)")
