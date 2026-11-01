"""
AURA Phase 9 — Reproducible Baseline Benchmark Harness.

Measures:
- Latency distributions (mean, p50, p95, min, max)
- Throughput (requests / second)
- Concurrency scaling (1, 8, 32 workers)
- Component breakdowns: RBAC, Rules, Persistence, Tools
- Deterministic mock baseline freezing into bench/results/baseline_report.json
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, List

# Ensure local repository root is prioritized
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aura.gateway import AuraGateway
from aura.jev.mock import MockJEVProvider
from aura.models import Decision, ExecutionStatus, RunContext, ToolRequest


@dataclass
class BenchmarkRunResult:
    concurrency: int
    total_requests: int
    duration_seconds: float
    throughput_rps: float
    mean_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    error_count: int
    component_breakdown_ms: dict[str, float]


def get_git_commit() -> str:
    """Retrieve current git commit hash."""
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "unknown_commit"


class AuraBenchmark:
    """Benchmark runner for AURA Enforcement Gateway."""

    def __init__(self, tmp_dir: str = "bench/results"):
        self.output_dir = Path(tmp_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(self.output_dir / "bench.db")
        self.jsonl_path = str(self.output_dir / "bench.jsonl")

        # Initialize Gateway with deterministic mock JEV
        self.gateway = AuraGateway(
            config_dir="config",
            db_path=self.db_path,
            jsonl_path=self.jsonl_path,
            jev_provider=MockJEVProvider(),
        )

        # In benchmark mode, set high throughput limits to test gateway scaling
        for agent_id, cfg in self.gateway.rate_limiter._agents.items():
            cfg.rate_limits["requests_per_minute"] = 1_000_000
            cfg.rate_limits["max_requests"] = 1_000_000
            cfg.rate_limits["max_concurrent"] = 200
        self.gateway.rate_limiter._max_requests = 1_000_000
        self.gateway.rate_limiter._max_concurrent = 200

    def _execute_single_request(self, i: int) -> tuple[float, bool]:
        """Execute a single protected tool request and measure roundtrip latency."""
        req = ToolRequest(
            agent_id="research_agent",
            tool_name="read_file",
            parameters={"doc_id": "doc:public_report"},
            idempotency_key=f"bench_key_{i}_{time.time_ns()}",
        )
        ctx = RunContext(agent_id="research_agent", agent_role="research")

        t0 = time.perf_counter()
        res = self.gateway.handle(req, ctx)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        success = (res.decision == Decision.ALLOW and res.execution_status == ExecutionStatus.COMPLETED)
        return elapsed_ms, success

    def run_benchmark(self, total_requests: int = 1000, concurrency_levels: list[int] = [1, 8, 32]) -> dict[str, Any]:
        """Run the full benchmark suite across specified concurrency levels."""
        print(f"\n=======================================================")
        print(f"  AURA PERFORMANCE BENCHMARK HARNESS")
        print(f"  Requests per tier: {total_requests}")
        print(f"  Concurrency tiers: {concurrency_levels}")
        print(f"=======================================================\n")

        # 1. Warmup (50 requests, excluded from stats)
        print("Executing 50 warmup iterations (excluded from stats)...")
        for i in range(50):
            self._execute_single_request(-i)

        results: list[BenchmarkRunResult] = []

        for c in concurrency_levels:
            print(f"\n[Tier Concurrency = {c}] Starting {total_requests} requests...")
            latencies: list[float] = []
            errors = 0

            start_tier = time.perf_counter()

            if c == 1:
                # Serial execution
                for i in range(total_requests):
                    lat, ok = self._execute_single_request(i)
                    latencies.append(lat)
                    if not ok:
                        errors += 1
            else:
                # Concurrent ThreadPool execution
                with concurrent.futures.ThreadPoolExecutor(max_workers=c) as pool:
                    futures = [pool.submit(self._execute_single_request, i) for i in range(total_requests)]
                    for fut in concurrent.futures.as_completed(futures):
                        lat, ok = fut.result()
                        latencies.append(lat)
                        if not ok:
                            errors += 1

            duration = time.perf_counter() - start_tier
            latencies.sort()

            mean_lat = sum(latencies) / len(latencies)
            p50_lat = latencies[int(len(latencies) * 0.50)]
            p95_lat = latencies[int(len(latencies) * 0.95)]
            min_lat = latencies[0]
            max_lat = latencies[-1]
            throughput = total_requests / duration if duration > 0 else 0.0

            # Component breakdown from telemetry
            telemetry_stats = self.gateway.telemetry.get_summary()

            run_res = BenchmarkRunResult(
                concurrency=c,
                total_requests=total_requests,
                duration_seconds=round(duration, 3),
                throughput_rps=round(throughput, 1),
                mean_latency_ms=round(mean_lat, 3),
                p50_latency_ms=round(p50_lat, 3),
                p95_latency_ms=round(p95_lat, 3),
                min_latency_ms=round(min_lat, 3),
                max_latency_ms=round(max_lat, 3),
                error_count=errors,
                component_breakdown_ms={
                    "mean_rbac_ms": telemetry_stats.get("mean_rbac_ms", 0.0),
                    "mean_rules_ms": telemetry_stats.get("mean_rule_evaluation_ms", 0.0),
                    "mean_persist_ms": telemetry_stats.get("mean_persistence_ms", 0.0),
                    "mean_tool_ms": telemetry_stats.get("mean_tool_execution_ms", 0.0),
                },
            )
            results.append(run_res)

            print(f"  -> Throughput: {throughput:.1f} req/s")
            print(f"  -> Latency: mean={mean_lat:.2f}ms | p50={p50_lat:.2f}ms | p95={p95_lat:.2f}ms")
            print(f"  -> Errors: {errors}")

        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "git_commit": get_git_commit(),
            "config": {
                "policy_version": self.gateway.policy_engine.policy_version,
                "db_mode": "WAL",
                "synchronous": "FULL",
                "jev_provider": "MockJEVProvider",
            },
            "results": [asdict(r) for r in results],
        }

        report_file = self.output_dir / "baseline_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"\n[OK] Baseline benchmark frozen to {report_file}")
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AURA Benchmark Harness")
    parser.add_argument("--requests", type=int, default=1000, help="Requests per concurrency tier")
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8, 32], help="Concurrency levels")
    args = parser.parse_args()

    bench = AuraBenchmark()
    bench.run_benchmark(total_requests=args.requests, concurrency_levels=args.concurrency)
