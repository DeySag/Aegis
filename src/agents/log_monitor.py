import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from src.agents.contracts import AlertEvent, LogEntry, Severity

LOG_DIR = Path(__file__).resolve().parents[2] / "data" / "logs"
TRAFFIC_LOG = LOG_DIR / "traffic.log"

EXECUTE_RE = re.compile(
    r"^(?P<ts>\S+ \S+) \| EXECUTE request: cmd='(?P<payload>.*)'$"
)
EXECUTE_RESP_RE = re.compile(
    r"^(?P<ts>\S+ \S+) \| EXECUTE response: cmd='(?P<payload>.*)' output='(?P<output>.*)'$"
)

SUSPICIOUS_RULES: list[tuple[str, re.Pattern]] = [
    ("echo", re.compile(r"\becho\b")),
    ("dir", re.compile(r"\bdir\b")),
    ("whoami", re.compile(r"\bwhoami\b")),
    ("ipconfig", re.compile(r"\bipconfig\b")),
    ("type", re.compile(r"\btype\b")),
    ("cat", re.compile(r"\bcat\b")),
    ("ls", re.compile(r"\bls\b")),
    ("ping", re.compile(r"\bping\b")),
    ("chain_&&", re.compile(r"&&")),
    ("chain_||", re.compile(r"\|\|")),
    ("chain_;", re.compile(r";\s*(?:echo|dir|whoami|cat|ls)")),
    ("subst_${}", re.compile(r"\$\{.*\}")),
    ("backtick", re.compile(r"`[^`]+`")),
    ("subst_$()", re.compile(r"\$\(.*\)")),
    ("aegis_test", re.compile(r"AEGIS_BREACH_OK")),
    ("loopback", re.compile(r"127\.0\.0\.1")),
]


def classify_severity(payload: str) -> Severity:
    high_indicators = ["whoami", "cat /etc", "type C:", "dir /s", "recursive"]
    if any(i in payload.lower() for i in high_indicators):
        return Severity.CRITICAL
    medium_indicators = ["ipconfig", "ifconfig", "dir", "ls"]
    if any(i in payload.lower() for i in medium_indicators):
        return Severity.HIGH
    return Severity.MEDIUM


def match_indicators(payload: str) -> list[str]:
    return [name for name, pat in SUSPICIOUS_RULES if pat.search(payload)]


def is_suspicious(payload: str) -> bool:
    return len(match_indicators(payload)) > 0


def parse_log_line(line: str) -> AlertEvent | None:
    m = EXECUTE_RE.match(line)
    if not m:
        return None
    payload = m.group("payload")
    if not is_suspicious(payload):
        return None
    entry = LogEntry(
        timestamp=m.group("ts"),
        source="sandbox_target",
        raw_message=line.strip(),
    )
    return AlertEvent(
        alert_id=uuid.uuid4().hex[:12],
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        endpoint="/execute",
        payload=payload,
        suspicious_indicators=match_indicators(payload),
        severity=classify_severity(payload),
        raw_logs=[entry],
    )


def tail_log(on_alert: Callable[[AlertEvent], None], interval: float = 1.0):
    TRAFFIC_LOG.parent.mkdir(parents=True, exist_ok=True)
    TRAFFIC_LOG.touch(exist_ok=True)
    pos = TRAFFIC_LOG.stat().st_size

    print(f"[LogMonitor] Watching {TRAFFIC_LOG} (offset={pos})")

    while True:
        try:
            cur = TRAFFIC_LOG.stat().st_size
            if cur < pos:
                pos = 0
            if cur > pos:
                with open(TRAFFIC_LOG, "r") as f:
                    f.seek(pos)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        alert = parse_log_line(line)
                        if alert:
                            on_alert(alert)
                pos = TRAFFIC_LOG.stat().st_size
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[LogMonitor] Error: {e}")
        time.sleep(interval)


def print_alert(alert: AlertEvent):
    print(
        f"[LogMonitor] ALERT {alert.alert_id} | "
        f"{alert.severity.value.upper()} | "
        f"payload={alert.payload}"
    )


if __name__ == "__main__":
    tail_log(on_alert=print_alert)
