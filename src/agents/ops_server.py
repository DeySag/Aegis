"""
Aegis Live Ops Server

Provides a real-time SSE feed of pipeline execution events to the
aegis_ops.html dashboard. Run alongside the sandbox target.

Usage:
    uvicorn src.agents.ops_server:ops_app --port 3000 --reload

Then open http://localhost:3000 in a browser.

NOTE: Single-viewer SSE design. The event_queue is consumed by one
StreamingResponse. Multiple simultaneous /events connections will
race for events. Sufficient for demo/recording; swap for
asyncio.Queue per client if multi-viewer is needed.
"""

import asyncio
import json
import os
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_proj = Path(__file__).resolve().parents[2]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from src.agents.log_monitor import tail_log
from src.agents.pipeline import run_pipeline

ops_app = FastAPI(title="Aegis Live Ops")

HTML_PATH = _proj / "presentation" / "aegis_ops.html"

# ── SSE event bus ─────────────────────────────────────────

event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
_main_loop: asyncio.AbstractEventLoop | None = None
alert_count = 0
patch_count = 0
loop_running = False


def emit(stage: str, data: dict[str, Any]) -> None:
    """Thread-safe push into the SSE event queue."""
    data["stage"] = stage
    data["type"] = "log"
    loop = _main_loop
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(event_queue.put(data), loop)


def emit_error(message: str) -> None:
    loop = _main_loop
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(event_queue.put({
            "type": "error",
            "message": message,
        }), loop)


# ── Routes ─────────────────────────────────────────────────

@ops_app.get("/")
async def index():
    if not HTML_PATH.exists():
        return HTMLResponse("<h1>Aegis Ops</h1><p>aegis_ops.html not found</p>", status_code=404)
    html = HTML_PATH.read_text(encoding="utf-8")
    return HTMLResponse(html)


@ops_app.get("/events")
async def event_stream(request: Request):
    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=8)
                yield f"data: {json.dumps(event)}\n\n"
            except asyncio.TimeoutError:
                yield f": keepalive\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Pipeline worker ────────────────────────────────────────

executor = ThreadPoolExecutor(max_workers=1)


def build_on_event() -> Callable[[str, dict], None]:
    def on_event(stage: str, data: dict[str, Any]) -> None:
        emit(stage, data)
    return on_event


def process_alert(alert: Any) -> None:
    global alert_count, patch_count
    alert_count += 1

    emit("stats", {"alerts_today": alert_count, "patches_today": patch_count, "queue": 1})

    try:
        result = run_pipeline(alert, apply=True, test=True, on_event=build_on_event())
        if result.get("applied"):
            patch_count += 1
        emit("stats", {
            "alerts_today": alert_count,
            "patches_today": patch_count,
            "queue": 0,
            "last_result": result.get("test_passed"),
        })
    except Exception as e:
        emit_error(f"Pipeline crashed: {type(e).__name__}: {e}")
        emit("stats", {"alerts_today": alert_count, "patches_today": patch_count, "queue": 0})


def pipeline_worker_loop() -> None:
    """Run log_monitor's tail_log in a background thread, dispatching to the pipeline."""
    try:
        tail_log(on_alert=process_alert, interval=1.0)
    except Exception as e:
        emit_error(f"Log monitor crashed: {e}")


# ── GPU telemetry ──────────────────────────────────────────

async def gpu_telemetry_loop() -> None:
    """Periodically emit GPU metrics — real ROCm data when available, mock drift otherwise."""
    rocm_provider = None
    try:
        import subprocess
        subprocess.run(["rocm-smi", "--version"], capture_output=True, check=True)
        from scripts.benchmark_gpu import ROCmGPUProvider
        rocm_provider = ROCmGPUProvider()
        model_name = "Qwen/Qwen2.5-14B-Instruct"
        vram_max = 48.0
        tok = 9.6
        lat = 2500
        ttft = 749
    except Exception:
        model_name = "llama-3-8b-instruct"
        vram_max = 24.0
        tok = 96
        lat = 640
        ttft = 210

    vram = 9.2
    vram_pct = round(vram / vram_max * 100, 1)
    util = 38
    power_w = 142
    temp_c = 58

    util_hist = [float(i % 40) * 2.5 for i in range(40)]
    tok_hist = [float(60 + (i % 30) * 2) for i in range(40)]
    util_idx = 0
    tok_idx = 0

    while True:
        await asyncio.sleep(2)

        if rocm_provider is not None:
            try:
                gpu = rocm_provider.collect_gpu_metrics()
                vram = round(gpu.vram_used_mb / 1024, 1)
                vram_pct = round((gpu.vram_used_mb / gpu.vram_total_mb) * 100, 1) if gpu.vram_total_mb > 0 else 0.0
                util = gpu.gpu_util_pct
                temp_c = gpu.temperature_c
                power_w = gpu.power_watts
            except Exception:
                pass
        else:
            gentle_drift = lambda v, s: max(0, v + (hash(str(time.time() + v)) % 10 - 5) * s * 0.1)
            vram = round(gentle_drift(vram, 0.3), 1)
            util = round(min(98, max(4, util + (hash(str(time.time())) % 7 - 3) * 2)))
            tok = round(min(260, max(20, tok + (hash(str(time.time() + 1)) % 11 - 5) * 3)))
            lat = round(min(1400, max(180, lat + (hash(str(time.time() + 2)) % 9 - 4) * 15)))
            ttft = round(min(600, max(80, ttft + (hash(str(time.time() + 3)) % 7 - 3) * 10)))
            power_w = round(min(260, max(60, power_w + (hash(str(time.time() + 4)) % 5 - 2) * 4)))
            temp_c = round(min(82, max(42, temp_c + (hash(str(time.time() + 5)) % 3 - 1) * 0.5)), 1)
            vram_pct = round(vram / vram_max * 100, 1)

        util_hist[util_idx % 40] = util
        tok_hist[tok_idx % 40] = tok
        util_idx += 1
        tok_idx += 1

        event = {
            "type": "gpu",
            "vram_gb": vram,
            "vram_max_gb": vram_max,
            "vram_pct": vram_pct,
            "util_pct": util,
            "tok_per_s": tok,
            "latency_ms": lat,
            "ttft_ms": ttft,
            "power_w": power_w,
            "temp_c": temp_c,
            "model": model_name,
            "util_hist": util_hist,
            "tok_hist": tok_hist,
        }
        await event_queue.put(event)


# ── Startup / shutdown ─────────────────────────────────────

@ops_app.on_event("startup")
async def startup():
    global _main_loop
    _main_loop = asyncio.get_running_loop()

    # Start the pipeline worker in a thread
    thread = threading.Thread(target=pipeline_worker_loop, daemon=True)
    thread.start()

    # Start GPU telemetry
    asyncio.create_task(gpu_telemetry_loop())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.agents.ops_server:ops_app", port=3000, reload=True)
