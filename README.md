# Aegis — Autonomous Cybersecurity AI

An advanced AI-powered cybersecurity system built for AMD compute. Aegis provides continuous network surveillance, instant threat detection, digital forensic analysis, root-cause vulnerability mapping, and automated code patching — all running locally on air-gapped hardware.

## Architecture

```
aegis/
├── src/
│   ├── agents/                      # Multi-agent AI orchestration
│   │   ├── config.py                #   LLM endpoint configuration (env vars)
│   │   ├── llm_client.py            #   OpenAI-compatible chat wrapper
│   │   ├── contracts.py             #   I/O schemas + system prompts
│   │   ├── log_monitor.py           #   Agent 1: tails traffic.log, emits alerts
│   │   ├── forensic_investigator.py #   Agent 2: LLM → heuristic fallback + source-line validation
│   │   ├── patch_engineer.py        #   Agent 3: LLM → lookup fallback + paren-depth tracking
│   │   ├── pipeline.py              #   Orchestrator: alert → investigate → patch → test
│   │   └── ops_server.py            #   FastAPI SSE backend for live ops dashboard
│   ├── sandbox_target/
│   │   ├── app.py                   #   Vulnerable FastAPI (command injection at line 34)
│   │   └── harness.py               #   Isolated sandbox test for patch validation
├── presentation/
│   ├── index.html                   # Reveal.js presentation deck (11 slides)
│   ├── demo_script.md               # Recordable demo script (~5 min)
│   └── aegis_ops.html               # SOC-style live ops terminal dashboard
├── scripts/
│   ├── attack.py                    # Attack simulator (Win/Linux/iOS payloads)
│   ├── stress_test_prompts.py       # Multi-model LLM stress test harness
│   └── benchmark_gpu.py             # GPU benchmark (mock/ROCm providers)
├── tests/
│   ├── test_prompt.py               # Multi-payload forensic investigator test
│   └── test_single.py               # Single-shot investigator test
├── data/
│   ├── logs/
│   │   └── traffic.log              # Sandbox access log (monitored by log_monitor)
├── .env                             # API key (gitignored)
├── .env.example                     # Template for .env
├── .gitignore
├── requirements.txt
└── README.md
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

## Running the Live Ops Dashboard

Two terminals + a browser:

```bash
# Terminal 1 — sandbox target
uvicorn src.sandbox_target.app:app --port 8000 --reload

# Terminal 2 — ops server
uvicorn src.agents.ops_server:ops_app --port 3000 --reload
```

Open http://localhost:3000 in a browser. The ops server:
- Tails `traffic.log` and runs the full pipeline on each alert
- Streams SSE events to the dashboard in real time
- Emits GPU telemetry (mock now, ROCm later)
- Falls back to scripted demo scenarios if the backend is unreachable

## Running the Agent Pipeline

```bash
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

## Stress Testing and GPU Benchmarking

```bash
# Multi-model stress test against the configured LLM endpoint
python scripts/stress_test_prompts.py

# GPU benchmark (use --provider rocm on AMD hardware)
python scripts/benchmark_gpu.py
```

Results are saved to `data/stress_test_results.json` and `data/gpu_benchmark_results.json`.

## How It Works

1. **Log Monitor** (`log_monitor.py`) — tails `data/logs/traffic.log`, detects 15+ suspicious patterns (echo, dir, whoami, `&&`, `;`, `|`, base64, URL-encoded chars, etc.), emits `AlertEvent` with severity classification.

2. **Forensic Investigator** (`forensic_investigator.py`) — **LLM path is primary.** Sends raw logs + full source file to the LLM. The source code copy sent to the LLM is annotated with `# <--- VULNERABLE LINE` at the `subprocess.run()` call (the real file on disk is unchanged). Post-hoc source-line validation then reads the actual file at the reported line (5-line window) to confirm an unsafe call pattern exists. If the LLM is unavailable, returns confidence < 0.70, or points to a line without an unsafe pattern, the system falls back to heuristic keyword matching (`VULN_SIGNATURES`).

3. **Patch Engineer** (`patch_engineer.py`) — sends the vulnerable code block to the LLM, which generates a secure replacement. Uses paren-depth tracking to locate the full multi-line block (e.g., the complete `subprocess.run(cmd, shell=True, ...)` call, not just its first line). Validates syntax with `ast.parse()` (handles indented code via `textwrap.dedent`/`textwrap.indent`). Retries up to 3 times with syntax error feedback. Falls back to a hardcoded `shlex.split(cmd) + no shell=True` lookup if all retries fail.

4. **Snapshot-Based Restore** — before each pipeline run, the original file content is captured and restored, eliminating cumulative patch damage. Previously, alerts 3+ in a session would fail because overlapping patches mangled the file.

5. **Sandbox Test Harness** (`harness.py`) — copies the app to an isolated temp dir, starts it on a free port, fires exploit + benign payloads, verifies exploits are blocked and legitimate requests still work. Distinguishes "syntax error in source" (`startup_failed`) from "exploits still work" for accurate diagnostics.

6. **Safety-Net** — three points of rejection: (**a**) low confidence (< 0.70), (**b**) source-line validation fails (LLM points to a safe line), (**c**) LLM returns no valid JSON at all. Each fires distinct `on_event` callbacks so the dashboard renders the exact reason.

## Agent I/O Contracts

| Agent | Input | Output |
|-------|-------|--------|
| Log Monitor | `traffic.log` lines | `AlertEvent` |
| Forensic Investigator | `AlertEvent` | `ForensicReport` |
| Patch Engineer | `ForensicReport` | `PatchProposal` |

All contracts are defined in `src/agents/contracts.py` as Pydantic models with strict JSON output requirements and granular confidence calibration guidelines.
