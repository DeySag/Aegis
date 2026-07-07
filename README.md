# Aegis — Autonomous Cybersecurity AI

An advanced AI-powered cybersecurity system built for AMD compute. Aegis provides continuous network surveillance, instant threat detection, digital forensic analysis, root-cause vulnerability mapping, and automated code patching — all running locally on air-gapped hardware.

## Architecture

```
src/
├── agents/                    # Multi-agent AI orchestration
│   ├── config.py              #   LLM endpoint configuration (env vars)
│   ├── llm_client.py          #   OpenAI-compatible chat wrapper
│   ├── contracts.py           #   I/O schemas (AlertEvent, ForensicReport, PatchProposal)
│   ├── log_monitor.py         #   Agent 1: tails traffic.log, emits alerts
│   ├── forensic_investigator.py  # Agent 2: LLM-driven code trace → heuristic fallback
│   ├── patch_engineer.py      #   Agent 3: LLM-generated fix → lookup fallback
│   └── pipeline.py            #   Orchestrator: alert → investigate → patch → test
├── sandbox_target/            # Vulnerable test application (FastAPI)
│   ├── app.py                 #   Deliberate command injection endpoint
│   └── harness.py             #   Isolated sandbox test for patch validation
├── patches/                   # Auto-generated security patches (future)
data/
├── logs/                      # Network traffic and stack traces
│   └── .gitkeep
scripts/
├── attack.py                  # Attack simulation script (Win/Linux/iOS payloads)
tests/                         # Test suite
```

## Setup

```bash
pip install -r requirements.txt
```

## LLM Setup (optional — enables AI-driven investigation & patching)

The pipeline uses an LLM for code tracing and patch generation. Without one,
it falls back to deterministic heuristics.

**Get a free API key from Groq** (no credit card required):
1. Go to https://console.groq.com/keys
2. Click "Create API Key"
3. Run:
```bash
cp .env.example .env
```
4. Edit `.env` and paste your key:
```
AEGIS_LLM_API_KEY=gsk_your_actual_key
```

The pipeline auto-loads `.env` via `python-dotenv`. That's it.

**Or set environment variables directly:**
```bash
set AEGIS_LLM_API_KEY=gsk_...              # Windows
export AEGIS_LLM_API_KEY=gsk_...           # Linux/macOS

set AEGIS_LLM_ENDPOINT=https://api.groq.com/openai/v1   # default
set AEGIS_LLM_MODEL=llama-3.3-70b-versatile             # default
```

**Using a different provider:** point `AEGIS_LLM_ENDPOINT` at any OpenAI-compatible
chat endpoint (Together, OpenAI, local ROCm server, etc.).

## Running the Sandbox (vulnerable)

```bash
uvicorn src.sandbox_target.app:app --reload --port 8000
```

## Running the Attack Simulator

```bash
python scripts/attack.py                          # auto-detect (Windows on this machine)
python scripts/attack.py -os linux                # Linux payloads
python scripts/attack.py -os ios                  # iOS payloads
```

## Running the Agent Pipeline

```bash
# Real-time log monitor (tails traffic.log)
python -m src.agents.log_monitor

# Full pipeline: investigate alert + generate patch (dry run)
python -m src.agents.pipeline

# Full pipeline with actual file patching + sandbox test
python -c "
from src.agents.contracts import AlertEvent, LogEntry
from src.agents.pipeline import run_pipeline
alert = AlertEvent(
    alert_id='demo',
    created_at='2026-07-08T00:00:00Z',
    endpoint='/execute',
    payload='dir src && whoami',
    suspicious_indicators=['dir', 'whoami', '&&'],
    severity='high',
    raw_logs=[LogEntry(timestamp='2026-07-08T00:00:00Z', source='sandbox_target',
              raw_message=\"EXECUTE request: cmd='dir src && whoami'\")]
)
result = run_pipeline(alert, apply=True, test=True)
print('Test passed:', result['test_passed'])
"
```

## Running the Sandbox Test Harness

```bash
python src/sandbox_target/harness.py
```

## How It Works

1. **Log Monitor** (`log_monitor.py`) — tails `data/logs/traffic.log`, detects suspicious commands (echo, dir, whoami, `&&`, etc.), emits `AlertEvent`.

2. **Forensic Investigator** (`forensic_investigator.py`) — sends the raw logs + full source file to the LLM, which identifies the exact file and line of the vulnerability. Falls back to heuristic keyword matching if the LLM is unavailable or returns low confidence (< 0.7).

3. **Patch Engineer** (`patch_engineer.py`) — sends the vulnerable code block to the LLM, which generates a secure replacement. Validates syntax with `ast.parse()` (handles indented code via `textwrap.dedent`). Retries up to 3 times with syntax error feedback. Falls back to a hardcoded `shlex.split(cmd)` lookup if all retries fail.

4. **Self-Correction Loop** — if `ast.parse()` fails, the error is fed back into the LLM prompt and the patch is regenerated (max 3 attempts). The sandbox test harness provides the final validation gate.

5. **Sandbox Test Harness** (`harness.py`) — copies the app to an isolated temp dir, starts it on a free port, fires exploit + benign payloads, verifies exploits are blocked and legitimate requests still work. No patch reaches the file system without passing this test.

## Agent I/O Contracts

| Agent | Input | Output |
|-------|-------|--------|
| Log Monitor | `traffic.log` lines | `AlertEvent` |
| Forensic Investigator | `AlertEvent` | `ForensicReport` |
| Patch Engineer | `ForensicReport` | `PatchProposal` |

All contracts are defined in `src/agents/contracts.py` as Pydantic models with strict JSON output requirements.
