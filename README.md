# Aegis — Autonomous Cybersecurity AI

An advanced AI-powered cybersecurity system built for AMD compute. Aegis provides continuous network surveillance, instant threat detection, digital forensic analysis, root-cause vulnerability mapping, and automated code patching — all running locally on air-gapped hardware.

## Architecture

```
src/
├── agents/           # Multi-agent AI orchestration (CrewAI/AutoGen)
│   └── contracts.py  # Structured I/O schemas between agents
├── sandbox_target/   # Vulnerable test application (FastAPI)
├── patches/          # Auto-generated security patches
data/
├── logs/             # Network traffic and stack traces
scripts/              # Attack simulation and utility scripts
tests/                # Test suite
```

## Setup

```bash
pip install -r requirements.txt
```

## Running the Sandbox

```bash
uvicorn src.sandbox_target.app:app --reload --port 8000
```

## Running the Attack Simulator

```bash
python scripts/attack.py
```
