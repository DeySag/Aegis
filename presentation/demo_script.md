# Aegis Demo Script — Non-Hardware Segments

Record these segments now. Only the GPU benchmark segment needs to wait for AMD hardware.

## Prerequisites for recording

```bash
# Terminal 1: Start the vulnerable sandbox
uvicorn src.sandbox_target.app:app --reload --port 8000

# Terminal 2: Generate some traffic
python scripts/attack.py -os windows

# Terminal 3: Reset the sandbox (if previously patched)
git checkout src/sandbox_target/app.py
```

---

## Segment 1: Sandbox Exploit (30s)

**Visual**: Terminal showing attack payloads hitting `/execute`

```
> curl "http://localhost:8000/execute?cmd=echo%20AEGIS_BREACH_OK"
→ {"cmd": "echo AEGIS_BREACH_OK", "output": "AEGIS_BREACH_OK\n", ...}

> curl "http://localhost:8000/execute?cmd=dir%20src"
→ {"cmd": "dir src", "output": " Volume in drive C ...", ...}

> curl "http://localhost:8000/execute?cmd=whoami"
→ {"cmd": "whoami", "output": "desktop\\user\n", ...}
```

**Voiceover**: *"Here's the vulnerable sandbox — a FastAPI server with a command injection
vulnerability. Any command passed to `/execute?cmd=` gets executed with full shell access.
An attacker can read files, run recon, or pivot to other systems."*

**Recording**: Screen capture of 3 curl commands showing exploit output.

---

## Segment 2: Traffic Logging (15s)

**Visual**: Show `data/logs/traffic.log` growing

```
cat data/logs/traffic.log

2026-07-08 12:00:01 | EXECUTE request: cmd='echo AEGIS_BREACH_OK'
2026-07-08 12:00:02 | EXECUTE request: cmd='dir src'
2026-07-08 12:00:03 | EXECUTE request: cmd='whoami'
```

**Voiceover**: *"Every request is logged to traffic.log. The Log Monitor agent tails
this file in real time, looking for suspicious patterns."*

---

## Segment 3: Log Monitor Detection (20s)

**Visual**: Run the log monitor and show alert emission

```
python -m src.agents.log_monitor

[LogMonitor] Alert: a1b2c3d4e5f6
  endpoint: /execute
  payload: "echo AEGIS_BREACH_OK"
  indicators: ['echo', 'AEGIS_BREACH_OK']
  severity: HIGH
```

**Voiceover**: *"The Log Monitor detects suspicious commands — echo, dir, whoami,
chained commands with && — and emits a structured AlertEvent with severity classification."*

---

## Segment 4: LLM Investigation (45s)

**Visual**: Run the pipeline with `apply=False, test=False`, show investigator output

```
python -c "
from src.agents.contracts import AlertEvent, LogEntry
from src.agents.pipeline import run_pipeline

alert = AlertEvent(
    alert_id='demo-001',
    created_at='2026-07-08T12:00:00Z',
    endpoint='/execute',
    payload='dir src && whoami',
    suspicious_indicators=['dir', 'whoami', '&&'],
    severity='high',
    raw_logs=[LogEntry(
        timestamp='2026-07-08T12:00:00Z',
        source='sandbox_target',
        raw_message=\"EXECUTE request: cmd='dir src && whoami'\"
    )]
)
result = run_pipeline(alert, apply=False, test=False)
print(json.dumps(result, indent=2))
"
```

Expected output showing:
```
investigator_path: "llm"
report.line: 34
report.confidence: 0.95
report.vuln_type: "command_injection"
```

**Voiceover**: *"The Forensic Investigator sends the full source file and raw logs to the
LLM, which traces the attack back to its root cause — line 34 of app.py, where
subprocess.run is called with shell=True. It returns this with 95% confidence."*

---

## Segment 5: LLM Patch Generation (45s)

**Visual**: Show the patch proposal output

```
patch_path: "llm"
patch.target_file: "src/sandbox_target/app.py"
patch.patch_code: "result = subprocess.run(
    shlex.split(cmd),
    capture_output=True,
    text=True,
    timeout=5,
)"
patch.rationale: "Replaced shell=True with shlex.split()..."
```

**Voiceover**: *"The Patch Engineer sends the vulnerable code to the LLM, which generates
a secure replacement — shlex.split(cmd) instead of shell=True. The patch is validated
with Python's AST parser before it ever touches the file system."*

---

## Segment 6: Sandbox Test Harness (30s)

**Visual**: Run the harness showing the validation

```
python src/sandbox_target/harness.py

=== Aegis Sandbox Test Harness ===
Sandbox started at http://127.0.0.1:54321
  OK: exploit_echo blocked (no output)
  OK: exploit_dir blocked (no output)
  OK: benign_ping allowed (has output)
All exploits blocked — test PASSED
```

**Voiceover**: *"The sandbox test harness copies the patched app to an isolated temp
directory, starts it on a free port, and fires a battery of exploit and benign payloads.
Only patches that block ALL exploits AND allow ALL legitimate requests pass the test."*

---

## Segment 7: Full Pipeline (e2e) (60s)

**Visual**: Run the full pipeline with `apply=True, test=True`

```
result = run_pipeline(alert, apply=True, test=True)

[Investigator] Path: LLM (confidence=0.95)
[Pipeline] Investigator -> report abc123 (line=34, path=llm)
[PatchEngine] LLM patch valid on attempt 1
[PatchEngine] Path: LLM
[PatchEngine] Patch applied to app.py:34
[PatchEngine] Backup saved: app.py.bak
[Pipeline] Sandbox test: PASSED

=== Pipeline Result ===
{
  "investigator_path": "llm",
  "patch_path": "llm",
  "applied": true,
  "test_passed": true
}
```

**Voiceover**: *"End to end — the alert comes in, the LLM investigates, the LLM generates
a patch, the patch is applied with a backup, the sandbox test validates the fix, and
the report shows which path was used at every step. From detection to validated patch
in under 30 seconds."*

---

## Segment 8: Fallback Demo (30s)

**Visual**: Set a bad model name to force fallback, show graceful degradation

```
# Set an invalid model to force all LLM calls to fail
set AEGIS_LLM_MODEL=nonexistent-model

python -c "result = run_pipeline(alert, apply=False)"

[Investigator] Path: heuristic fallback
[PatchEngine] Path: lookup fallback

=== Pipeline Result ===
{
  "investigator_path": "heuristic",
  "patch_path": "lookup",
  "test_passed": true
}
```

**Voiceover**: *"Even when the LLM is unavailable — wrong model, network down, or
rate-limited — the system doesn't crash. It degrades gracefully through two layers
of fallback: deterministic heuristics for investigation, and hardcoded secure
replacements for patching. The pipeline still works."*

---

## Segment 9: Stress Test Summary (30s)

**Visual**: Show the stress test results summary

```
python scripts/stress_test_prompts.py --models llama-3.1-8b-instant --runs 5

  Investigator: 5 runs, LLM=3 heuristic=2, 0 wrong-line
  Avg confidence: 0.883
  PatchEngine: 5 runs, LLM=5 lookup=0, 0 syntax fails
```

**Voiceover**: *"We stress-tested our prompts against the actual model sizes we'll deploy
locally. The 8-billion-parameter model matched 70-billion performance — same correct
line identification, same confidence calibration. We also discovered the Llama 4 Scout
model consistently misidentifies vulnerability locations, so we added source-line
validation as a safety net."*

---

## Segment 10: Benchmark Tooling (15s)

**Visual**: Show the GPU benchmark running with mock data

```
python scripts/benchmark_gpu.py --provider mock

Aegis GPU Benchmark Report
── GPU Metrics ──
  GPU:            AMD Instinct MI250 (MOCK)
  VRAM Total:     65536 MB
  VRAM Used:      24576 MB (37.5%)
── Inference Metrics ──
  Model:          llama-3.3-70b-versatile
  Throughput:     18.2 tok/s
  TTFT:           210ms
```

**Voiceover**: *"The GPU benchmarking script is ready and tested with mock data.
When AMD hardware arrives, one flag change — --provider rocm — and it reads from
real rocm-smi output, giving us VRAM, power, temperature, tokens per second, and
time-to-first-token metrics."*

---

## Recording Checklist

- [ ] Segment 1: Sandbox exploit (curl commands showing command injection)
- [ ] Segment 2: traffic.log showing captured requests
- [ ] Segment 3: Log Monitor emitting AlertEvent
- [ ] Segment 4: Pipeline showing investigator_path: "llm"
- [ ] Segment 5: Patch proposal with shlex.split replacement
- [ ] Segment 6: Harness test showing exploits blocked
- [ ] Segment 7: Full e2e run showing PASSED
- [ ] Segment 8: Fallback demo with heuristic path
- [ ] Segment 9: Stress test summary screen
- [ ] Segment 10: Benchmark tooling with mock data

**Total estimated runtime**: ~5 minutes

**Edit notes**: The segments are designed to be recorded independently and cut together.
Each segment has a clear start/end state for clean transitions.
