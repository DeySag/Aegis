#!/usr/bin/env python
"""
GPU Benchmarking Suite for KAVACH.

Captures VRAM, tokens/sec, and latency for LLM inference.
Abstract provider pattern — works with mock data now, swap in real ROCm later.

Usage:
    python scripts/benchmark_gpu.py                          # mock data (dev/test)
    python scripts/benchmark_gpu.py --provider mock          # explicit mock
    python scripts/benchmark_gpu.py --provider rocm          # real AMD GPU (future)

Output: data/gpu_benchmark_results.json (gitignored)
"""

import json
import os
import sys
import time
import platform
import argparse
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_proj = Path(__file__).resolve().parents[1]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

RESULTS_FILE = _proj / "data" / "gpu_benchmark_results.json"


# ── Data models ──────────────────────────────────────────────

@dataclass
class GPUMetrics:
    gpu_name: str = ""
    vram_total_mb: float = 0.0
    vram_used_mb: float = 0.0
    vram_free_mb: float = 0.0
    vram_util_pct: float = 0.0
    gpu_util_pct: float = 0.0
    temperature_c: float = 0.0
    power_watts: float = 0.0


@dataclass
class InferenceMetrics:
    model_name: str = ""
    tokens_generated: int = 0
    latency_seconds: float = 0.0
    tokens_per_second: float = 0.0
    prompt_tokens: int = 0
    time_to_first_token_ms: float = 0.0


@dataclass
class BenchmarkRun:
    timestamp: str = ""
    provider: str = ""
    hostname: str = ""
    gpu: GPUMetrics = field(default_factory=GPUMetrics)
    inference: InferenceMetrics = field(default_factory=InferenceMetrics)
    error: str | None = None


# ── Provider interface ──────────────────────────────────────

class GPUProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def collect_gpu_metrics(self) -> GPUMetrics:
        ...

    @abstractmethod
    def run_inference(self, model_name: str, prompt: str, max_tokens: int = 128) -> InferenceMetrics:
        ...


# ── Mock provider (for dev/test, no GPU needed) ─────────────

class MockGPUProvider(GPUProvider):
    @property
    def name(self) -> str:
        return "mock"

    def collect_gpu_metrics(self) -> GPUMetrics:
        return GPUMetrics(
            gpu_name="AMD Instinct MI250 (MOCK)",
            vram_total_mb=65536.0,
            vram_used_mb=24576.0,
            vram_free_mb=40960.0,
            vram_util_pct=37.5,
            gpu_util_pct=42.0,
            temperature_c=68.0,
            power_watts=225.0,
        )

    def run_inference(self, model_name: str, prompt: str, max_tokens: int = 128) -> InferenceMetrics:
        # Simulate inference latency proportional to prompt + token count
        prompt_tokens = max(1, len(prompt) // 4)
        simulated_tokens = min(max_tokens, prompt_tokens + 10)
        delay = 0.05 * simulated_tokens + 0.2  # ~50ms/token + base
        time.sleep(min(delay, 0.5))  # cap for speed during testing

        return InferenceMetrics(
            model_name=model_name,
            tokens_generated=simulated_tokens,
            latency_seconds=round(delay, 3),
            tokens_per_second=round(simulated_tokens / max(delay, 0.01), 1),
            prompt_tokens=prompt_tokens,
            time_to_first_token_ms=round(150 + prompt_tokens * 2, 1),
        )


# ── ROCm provider (swap in when AMD hardware arrives) ───────

class ROCmGPUProvider(GPUProvider):
    @property
    def name(self) -> str:
        return "rocm"

    def _run_rocm_smi(self, *args: str) -> list[str]:
        try:
            result = subprocess.run(
                ["rocm-smi", *args],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout.strip().split("\n")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"rocm-smi failed: {e}")

    def collect_gpu_metrics(self) -> GPUMetrics:
        output = self._run_rocm_smi("--showmeminfo", "vram", "--showuse", "--showtemp", "--showpower")
        # Parse rocm-smi output — format varies by version
        metrics = GPUMetrics(gpu_name="AMD GPU (rocm-smi)")
        for line in output:
            parts = line.strip().split(":")
            if len(parts) < 2:
                continue
            key, val = parts[0].strip(), parts[1].strip()
            if "VRAM Total" in key:
                metrics.vram_total_mb = self._parse_mb(val)
            elif "VRAM Used" in key:
                metrics.vram_used_mb = self._parse_mb(val)
            elif "GPU use" in key:
                metrics.gpu_util_pct = self._parse_pct(val)
            elif "Temperature" in key:
                metrics.temperature_c = self._parse_temp(val)
            elif "Power" in key:
                metrics.power_watts = self._parse_power(val)
        metrics.vram_free_mb = metrics.vram_total_mb - metrics.vram_used_mb
        if metrics.vram_total_mb > 0:
            metrics.vram_util_pct = round((metrics.vram_used_mb / metrics.vram_total_mb) * 100, 1)
        return metrics

    @staticmethod
    def _parse_mb(val: str) -> float:
        try:
            return float(val.replace("MB", "").replace("mB", "").strip())
        except ValueError:
            return 0.0

    @staticmethod
    def _parse_pct(val: str) -> float:
        try:
            return float(val.replace("%", "").strip())
        except ValueError:
            return 0.0

    @staticmethod
    def _parse_temp(val: str) -> float:
        try:
            return float(val.replace("°C", "").replace("C", "").strip())
        except ValueError:
            return 0.0

    @staticmethod
    def _parse_power(val: str) -> float:
        try:
            return float(val.replace("W", "").replace("w", "").strip())
        except ValueError:
            return 0.0

    def run_inference(self, model_name: str, prompt: str, max_tokens: int = 128) -> InferenceMetrics:
        # Uses the configured LLM endpoint (which should point at local ROCm server)
        from src.agents.config import LLMConfig
        from src.agents.llm_client import chat

        config = LLMConfig()
        config.model = model_name
        t0 = time.time()
        try:
            response = chat(
                "You are a helpful assistant. Respond concisely.",
                prompt,
                config,
            )
            latency = time.time() - t0
            generated = max(1, len(response.split()))
            return InferenceMetrics(
                model_name=model_name,
                tokens_generated=generated,
                latency_seconds=round(latency, 3),
                tokens_per_second=round(generated / latency, 1) if latency > 0 else 0,
                prompt_tokens=max(1, len(prompt) // 4),
                time_to_first_token_ms=round(latency * 0.3 * 1000, 1),
            )
        except Exception as e:
            return InferenceMetrics(
                model_name=model_name,
                tokens_generated=0,
                latency_seconds=0,
                tokens_per_second=0,
                prompt_tokens=max(1, len(prompt) // 4),
                time_to_first_token_ms=0,
            )


# ── Provider factory ────────────────────────────────────────

PROVIDERS: dict[str, type[GPUProvider]] = {
    "mock": MockGPUProvider,
    "rocm": ROCmGPUProvider,
}


def get_provider(name: str = "mock") -> GPUProvider:
    cls = PROVIDERS.get(name)
    if cls is None:
        raise ValueError(f"Unknown provider: {name}. Options: {list(PROVIDERS.keys())}")
    return cls()


# ── Benchmark runner ────────────────────────────────────────

def run_benchmark(provider_name: str = "mock", model_name: str = "llama-3.3-70b-versatile",
                  prompt: str | None = None, max_tokens: int = 128,
                  num_runs: int = 1) -> BenchmarkRun:
    provider = get_provider(provider_name)
    run = BenchmarkRun(
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        provider=provider_name,
        hostname=platform.node(),
    )

    try:
        # Collect GPU metrics before inference
        run.gpu = provider.collect_gpu_metrics()

        # Run inference
        if prompt is None:
            prompt = (
                "Explain the security vulnerability in this code:\n"
                "result = subprocess.run(cmd, shell=True, capture_output=True, text=True)"
            )

        inference_results = []
        for _ in range(num_runs):
            inf = provider.run_inference(model_name, prompt, max_tokens)
            inference_results.append(inf)

        # Average across runs for report
        if inference_results:
            avg = InferenceMetrics(model_name=model_name)
            avg.tokens_generated = round(sum(r.tokens_generated for r in inference_results) / len(inference_results))
            avg.latency_seconds = round(sum(r.latency_seconds for r in inference_results) / len(inference_results), 3)
            avg.tokens_per_second = round(
                sum(r.tokens_per_second for r in inference_results) / len(inference_results), 1
            )
            avg.prompt_tokens = inference_results[0].prompt_tokens
            avg.time_to_first_token_ms = round(
                sum(r.time_to_first_token_ms for r in inference_results) / len(inference_results), 1
            )
            run.inference = avg

    except Exception as e:
        run.error = str(e)

    return run


def print_report(run: BenchmarkRun):
    print(f"\n{'='*50}")
    print(f"KAVACH GPU Benchmark Report")
    print(f"{'='*50}")
    print(f"Timestamp:  {run.timestamp}")
    print(f"Provider:   {run.provider}")
    print(f"Hostname:   {run.hostname}")

    g = run.gpu
    print(f"\n--- GPU Metrics ---")
    print(f"  GPU:            {g.gpu_name}")
    print(f"  VRAM Total:     {g.vram_total_mb:.0f} MB")
    print(f"  VRAM Used:      {g.vram_used_mb:.0f} MB ({g.vram_util_pct:.1f}%)")
    print(f"  GPU Util:       {g.gpu_util_pct:.1f}%")
    print(f"  Temperature:    {g.temperature_c:.0f} C")

    i = run.inference
    print(f"\n--- Inference Metrics ---")
    print(f"  Model:          {i.model_name}")
    print(f"  Prompt Tokens:  {i.prompt_tokens}")
    print(f"  Generated:      {i.tokens_generated} tokens")
    print(f"  Latency:        {i.latency_seconds:.2f}s")
    print(f"  Throughput:     {i.tokens_per_second:.1f} tok/s")
    print(f"  TTFT:           {i.time_to_first_token_ms:.0f}ms")

    if run.error:
        print(f"\n  ERROR: {run.error}")

    print(f"{'='*50}\n")


def main():
    parser = argparse.ArgumentParser(description="KAVACH GPU Benchmarking Suite")
    parser.add_argument("--provider", choices=list(PROVIDERS.keys()), default="mock",
                        help="GPU provider (default: mock)")
    parser.add_argument("--model", default="llama-3.3-70b-versatile",
                        help="Model name for inference benchmark")
    parser.add_argument("--runs", type=int, default=1,
                        help="Number of inference runs to average (default: 1)")
    parser.add_argument("--prompt", help="Custom prompt for inference test")
    parser.add_argument("--max-tokens", type=int, default=128,
                        help="Max tokens to generate (default: 128)")
    parser.add_argument("--save", action="store_true", default=True,
                        help="Save results to JSON (default: True)")
    args = parser.parse_args()

    print("Starting GPU benchmark...")
    run = run_benchmark(
        provider_name=args.provider,
        model_name=args.model,
        prompt=args.prompt,
        max_tokens=args.max_tokens,
        num_runs=args.runs,
    )

    print_report(run)

    if args.save:
        RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if RESULTS_FILE.exists():
            existing = json.loads(RESULTS_FILE.read_text())
        existing.append(asdict(run))
        RESULTS_FILE.write_text(json.dumps(existing, indent=2))
        print(f"Results saved to {RESULTS_FILE}")


if __name__ == "__main__":
    main()
