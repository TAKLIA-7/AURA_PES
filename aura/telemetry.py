"""AURA Telemetry and Performance Metrics.

Correlates cost, latency, throughput, and fast-path rates by trace ID.
Separates high-volume telemetry from the security audit trail.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field


class OperationMetrics(BaseModel):
    """Metrics for a single trace / operation."""
    trace_id: str
    action: str
    agent_id: str
    decision: str
    fast_path: bool = True
    jev_invoked: bool = False
    jev_tokens: int = 0
    gateway_duration_ms: float = 0.0
    adapter_duration_ms: float = 0.0
    total_duration_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class TelemetryCollector:
    """Thread-safe collector for runtime performance and cost metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._metrics: list[OperationMetrics] = []
        self._by_trace: dict[str, list[OperationMetrics]] = defaultdict(list)

    def record(self, metric: OperationMetrics) -> None:
        with self._lock:
            self._metrics.append(metric)
            self._by_trace[metric.trace_id].append(metric)

    def get_summary(self) -> dict[str, Any]:
        """Compute aggregated performance summary."""
        with self._lock:
            total = len(self._metrics)
            if total == 0:
                return {
                    "total_operations": 0,
                    "fast_path_rate": 1.0,
                    "avg_duration_ms": 0.0,
                    "p95_duration_ms": 0.0,
                    "total_jev_tokens": 0,
                }

            fast_path_count = sum(1 for m in self._metrics if m.fast_path)
            total_tokens = sum(m.jev_tokens for m in self._metrics)
            durations = sorted(m.total_duration_ms for m in self._metrics)

            avg_dur = sum(durations) / total
            p95_idx = int(0.95 * total)
            p95_dur = durations[min(p95_idx, total - 1)]

            return {
                "total_operations": total,
                "fast_path_count": fast_path_count,
                "fast_path_rate": fast_path_count / total,
                "avg_duration_ms": round(avg_dur, 2),
                "p95_duration_ms": round(p95_dur, 2),
                "total_jev_tokens": total_tokens,
            }

    def reset(self) -> None:
        with self._lock:
            self._metrics.clear()
            self._by_trace.clear()
