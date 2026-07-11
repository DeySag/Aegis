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
        # Send an immediate event so the client (and any proxy in between)
        # sees bytes right away rather than waiting on the first real alert.
        yield f": connected\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=8)
                yield f"data: {json.dumps(event)}\n\n"
            except asyncio.TimeoutError:
                yield f": keepalive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            # Without these, reverse proxies (including cloudflared tunnels)
            # commonly buffer the whole response instead of streaming it,
            # so nothing appears in the browser until the connection ends.
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


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

# ── GPU telemetry ──────────────────────────────────────────

def _load_gpu_provider():
    """Reuse scripts/benchmark_gpu.py's ROCmGPUProvider — real rocm-smi
    data when available, falls back to mock drift if the tool/hardware
    isn't present (e.g. developing off the GPU box)."""
    scripts_dir = _proj / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from benchmark_gpu import ROCmGPUProvider  # noqa: E402
        provider = ROCmGPUProvider()
        # Probe once so we fail fast to mock instead of erroring every 2s
        provider.collect_gpu_metrics()
        return provider
    except Exception as e:
        print(f"[ops_server] rocm-smi unavailable ({e}) — using mock GPU telemetry")
        return None


async def gpu_telemetry_loop() -> None:
    """Periodically emit GPU metrics. Real rocm-smi readings when the
    ROCmGPUProvider can talk to hardware; deterministic mock drift
    otherwise, so the panel is never blank."""
    provider = _load_gpu_provider()
    model_name = os.environ.get("AEGIS_LLM_MODEL", "unknown-model")

    # token-throughput / latency aren't exposed by rocm-smi (that's an
    # inference-server metric, not a GPU metric) — track a lightweight
    # rolling mock for those specifically even in "real" mode, driven by
    # whether the pipeline is actively mid-run (best-effort proxy).
    tok = 96.0
    lat = 640.0
    ttft = 210.0

    vram_max = 24.0
    vram = 9.2
    util = 38
    power_w = 142
    temp_c = 58

    util_hist = [float(i % 40) * 2.5 for i in range(40)]
    tok_hist = [float(60 + (i % 30) * 2) for i in range(40)]
    util_idx = 0
    tok_idx = 0

    while True:
        await asyncio.sleep(2)

        if provider is not None:
            try:
                m = provider.collect_gpu_metrics()
                vram_max = max(m.vram_total_mb / 1024.0, 0.1)
                vram = m.vram_used_mb / 1024.0
                util = m.gpu_util_pct
                power_w = m.power_watts
                temp_c = m.temperature_c
                gpu_label = m.gpu_name
            except Exception as e:
                emit_error(f"rocm-smi read failed, switching to mock: {e}")
                provider = None
                gpu_label = "AMD GPU (mock — rocm-smi failed mid-run)"
        if provider is None:
            gentle_drift = lambda v, s: max(0, v + (hash(str(time.time() + v)) % 10 - 5) * s * 0.1)
            vram = gentle_drift(vram, 0.3)
            util = min(98, max(4, util + (hash(str(time.time())) % 7 - 3) * 2))
            power_w = min(260, max(60, power_w + (hash(str(time.time() + 4)) % 5 - 2) * 4))
            temp_c = min(82, max(42, temp_c + (hash(str(time.time() + 5)) % 3 - 1) * 0.5))
            gpu_label = "AMD GPU (mock)"

        # tok/s, latency, ttft: mock-drift regardless (see note above)
        tok = min(260, max(20, tok + (hash(str(time.time() + 1)) % 11 - 5) * 3))
        lat = min(1400, max(180, lat + (hash(str(time.time() + 2)) % 9 - 4) * 15))
        ttft = min(600, max(80, ttft + (hash(str(time.time() + 3)) % 7 - 3) * 10))

        vram = round(vram, 1)
        util = round(util)
        tok = round(tok)
        lat = round(lat)
        ttft = round(ttft)
        power_w = round(power_w)
        temp_c = round(temp_c, 1)

        util_hist[util_idx % 40] = util
        tok_hist[tok_idx % 40] = tok
        util_idx += 1
        tok_idx += 1

        event = {
            "type": "gpu",
            "vram_gb": vram,
            "vram_max_gb": vram_max,
            "vram_pct": round(vram / vram_max * 100, 1) if vram_max else 0,
            "util_pct": util,
            "tok_per_s": tok,
            "latency_ms": lat,
            "ttft_ms": ttft,
            "power_w": power_w,
            "temp_c": temp_c,
            "model": f"{model_name} · {gpu_label}",
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
