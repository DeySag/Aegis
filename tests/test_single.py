import sys
sys.path.insert(0, "src")

from src.agents.forensic_investigator import investigate_llm
from src.agents.config import LLMConfig
from src.agents.contracts import AlertEvent, LogEntry, Severity
from datetime import datetime, timezone

cfg = LLMConfig()
cfg.max_retries = 0
cfg.timeout = 15

alert = AlertEvent(
    alert_id="quick-test",
    created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    endpoint="/execute",
    payload="echo test",
    suspicious_indicators=["echo"],
    severity=Severity.MEDIUM,
    raw_logs=[LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source="sandbox_target",
        raw_message="EXECUTE request: cmd='echo test'",
    )],
)
result = investigate_llm(alert, config_override=cfg)
if result:
    print(f"Line: {result.line}, Conf: {result.confidence}")
else:
    print("None")
