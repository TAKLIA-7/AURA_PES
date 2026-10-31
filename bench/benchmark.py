"""AURA Performance & Baseline Benchmark Harness.

Measures:
  - Fast-path deterministic throughput & latency (1,000 requests per run)
  - Concurrency scaling across 1, 8, and 32 threads
  - Fast-path hit rate and p50, p95, p99 latency distributions
"""

from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path
from typing import Any

from aura.gateway import AuraGateway
from aura.models import AgentIdentity, AuraRequest, RunContext, ToolAction


def run_benchmark_path(
    gateway: AuraGateway,
    num_requests: int = 1000,
    concurrency: int = 1,
) -> dict[str, Any]:
    """Execute *num_requests* against the gateway under *concurrency*."""
    agent = AgentIdentity(agent_id="admin_agent", role="admin")
    if gateway.rate_limiter:
        gateway.rate_limiter.default_limit = 1000000
        gateway.rate_limiter.role_limits["admin"] = 1000000
        gateway.rate_limiter.reset()
    latencies: list[float] = []

    def make_call(i: int) -> float:
        req = AuraRequest(
            request_id=f"bench-{concurrency}-{i}",
            action=ToolAction.READ_FILE,
            params={"doc_id": "public/readme"},
            agent=agent,
        )
        ctx = RunContext(request=req)
        t0 = time.perf_counter()
        res = gateway.handle(req, ctx)
        t1 = time.perf_counter()
        assert res.execution_status == "success"
        return (t1 - t0) * 1000.0

    start_total = time.perf_counter()
    if concurrency == 1:
        for i in range(num_requests):
            latencies.append(make_call(i))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(make_call, i) for i in range(num_requests)]
            for f in concurrent.futures.as_completed(futures):
                latencies.append(f.result())

    total_time = time.perf_counter() - start_total
    latencies.sort()

    p50 = latencies[int(0.50 * len(latencies))]
    p95 = latencies[int(0.95 * len(latencies))]
    p99 = latencies[int(0.99 * len(latencies))]
    throughput = num_requests / total_time

    return {
        "requests": num_requests,
        "concurrency": concurrency,
        "total_time_seconds": round(total_time, 3),
        "throughput_ops_sec": round(throughput, 1),
        "p50_latency_ms": round(p50, 3),
        "p95_latency_ms": round(p95, 3),
        "p99_latency_ms": round(p99, 3),
    }


def main() -> None:
    fixtures_path = Path(__file__).resolve().parent.parent / "config"
    gw = AuraGateway.create_default(config_dir=str(fixtures_path))

    print("=========================================================")
    print("      AURA Gateway Performance Benchmark Baseline        ")
    print("=========================================================")

    # Warmup
    print("Warming up gateway...")
    run_benchmark_path(gw, num_requests=100, concurrency=1)

    for conc in (1, 8, 32):
        print(f"\nRunning 1,000 actions at concurrency={conc}...")
        metrics = run_benchmark_path(gw, num_requests=1000, concurrency=conc)
        print(f"  Throughput : {metrics['throughput_ops_sec']} ops/sec")
        print(f"  p50 Latency: {metrics['p50_latency_ms']} ms")
        print(f"  p95 Latency: {metrics['p95_latency_ms']} ms")
        print(f"  p99 Latency: {metrics['p99_latency_ms']} ms")

    print("\nBenchmark completed successfully.")


if __name__ == "__main__":
    main()
