# Aegis — Autonomous Cybersecurity AI

An advanced AI-powered cybersecurity system built for AMD compute. Aegis provides continuous network surveillance, instant threat detection, digital forensic analysis, root-cause vulnerability mapping, and automated code patching — all running locally on air-gapped hardware.

## Architecture

```
src/
├── agents/                    # Multi-agent AI orchestration
│   ├── contracts.py           #   I/O schemas (AlertEvent, ForensicReport, PatchProposal)
│   ├── log_monitor.py         #   Agent 1: tails traffic.log, emits alerts
│   ├── forensic_investigator.py  # Agent 2: maps payloads to file + line number
│   ├── patch_engineer.py      #   Agent 3: generates & applies secure code patches
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

# Pipeline with actual file patching + sandbox test
python -c "from src.agents.pipeline import run_pipeline; from src.agents.contracts import AlertEvent, LogEntry; ..."
```

## Running the Sandbox Test Harness

```bash
python src/sandbox_target/harness.py
```

## How It Works

1. **Log Monitor** (`log_monitor.py`) — tails `data/logs/traffic.log`, detects suspicious commands (echo, dir, whoami, `&&`, etc.), emits `AlertEvent`.
2. **Forensic Investigator** (`forensic_investigator.py`) — maps payload indicators to the exact vulnerable code location (`app.py:35` — `subprocess.run(cmd, shell=True)`). Returns `ForensicReport` with file, line, confidence.
3. **Patch Engineer** (`patch_engineer.py`) — generates a secure replacement (`shlex.split(cmd)` instead of `shell=True`), validates syntax with `ast.parse()`, applies to file with backup, triggers hot-reload.
4. **Retry Loop** — if `ast.parse()` fails, the error is fed back and the patch is regenerated (max 2 attempts).
5. **Sandbox Test Harness** (`harness.py`) — copies the app to an isolated temp dir, applies the patch, fires exploit + benign payloads, verifies exploits are blocked and legitimate requests still work.

## Agent I/O Contracts

| Agent | Input | Output |
|-------|-------|--------|
| Log Monitor | `traffic.log` lines | `AlertEvent` |
| Forensic Investigator | `AlertEvent` | `ForensicReport` |
| Patch Engineer | `ForensicReport` | `PatchProposal` |

All contracts are defined in `src/agents/contracts.py` as Pydantic models with strict JSON output requirements.
