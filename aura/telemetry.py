"""
AURA Telemetry — Operational metrics collection.

This module is **separate from the security audit trail**.  It tracks
performance counters, latency distributions, token consumption, and
estimated costs so operators can monitor gateway health without
querying the tamper-evident audit log.

All state is in-memory and thread-safe.  There is no persistence
requirement — metrics are expected to be consumed or scraped before
the process exits.
"""

from __future__ import annotations

import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# ──────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────


@dataclass
class OperationMetrics:
    """Per-operation performance and cost counters.

    Each field is zero-valued by default so callers can populate
    only the measurements they collected.
    """

    trace_id: str = ""
    validation_time_ms: float = 0.0
    rbac_time_ms: float = 0.0
    rule_evaluation_time_ms: float = 0.0
    jev_latency_ms: float = 0.0
    approval_wait_ms: float = 0.0
    persistence_time_ms: float = 0.0
    tool_execution_time_ms: float = 0.0
    end_to_end_time_ms: float = 0.0
    jev_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0


# ──────────────────────────────────────────────
# Timer
# ──────────────────────────────────────────────


class Timer:
    """Context manager for high-resolution timing.

    Usage::

        with telemetry.timer() as t:
            do_work()
        print(t.elapsed_ms)
    """

    def __init__(self) -> None:
        self.start_time: float = 0.0
        self.elapsed_ms: float = 0.0

    def __enter__(self) -> Timer:
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args: object) -> None:
        self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000.0


# ──────────────────────────────────────────────
# Collector
# ──────────────────────────────────────────────


class TelemetryCollector:
    """Thread-safe in-memory metrics aggregator.

    Stores a rolling window of ``OperationMetrics`` and exposes
    aggregate summary statistics on demand.
    """

    def __init__(self, max_history: int = 10_000) -> None:
        self._metrics: list[OperationMetrics] = []
        self._lock: threading.Lock = threading.Lock()
        self._max_history: int = max_history

    def record(self, metrics: OperationMetrics) -> None:
        """Record a completed operation's metrics.

        Old entries are evicted when ``max_history`` is exceeded.

        Args:
            metrics: The ``OperationMetrics`` snapshot to store.
        """
        with self._lock:
            self._metrics.append(metrics)
            # Trim to keep memory bounded
            if len(self._metrics) > self._max_history:
                self._metrics = self._metrics[-self._max_history:]

    def timer(self) -> Timer:
        """Return a new :class:`Timer` context manager.

        Convenience factory so callers don't need to import ``Timer``
        separately.
        """
        return Timer()

    def get_summary(self) -> dict[str, Any]:
        """Compute aggregate summary statistics over recorded metrics.

        Returns:
            A dict with ``total_operations``, ``total_jev_calls``,
            per-phase latency stats (``mean``, ``p50``, ``p95``,
            ``max``), and cumulative token/cost totals.  Returns
            an empty-summary sentinel if no metrics have been recorded.
        """
        with self._lock:
            snapshot = list(self._metrics)

        if not snapshot:
            return {
                "total_operations": 0,
                "total_jev_calls": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "total_estimated_cost_usd": 0.0,
                "latency": {},
            }

        def _latency_stats(values: list[float]) -> dict[str, float]:
            """Compute mean, p50, p95, max for a list of floats."""
            if not values:
                return {"mean": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0}
            sorted_vals = sorted(values)
            return {
                "mean": round(statistics.mean(sorted_vals), 3),
                "p50": round(_percentile(sorted_vals, 50), 3),
                "p95": round(_percentile(sorted_vals, 95), 3),
                "max": round(sorted_vals[-1], 3),
            }

        return {
            "total_operations": len(snapshot),
            "total_jev_calls": sum(m.jev_calls for m in snapshot),
            "total_input_tokens": sum(m.input_tokens for m in snapshot),
            "total_output_tokens": sum(m.output_tokens for m in snapshot),
            "total_estimated_cost_usd": round(
                sum(m.estimated_cost_usd for m in snapshot), 6
            ),
            "latency": {
                "end_to_end": _latency_stats(
                    [m.end_to_end_time_ms for m in snapshot]
                ),
                "validation": _latency_stats(
                    [m.validation_time_ms for m in snapshot]
                ),
                "rbac": _latency_stats(
                    [m.rbac_time_ms for m in snapshot]
                ),
                "rule_evaluation": _latency_stats(
                    [m.rule_evaluation_time_ms for m in snapshot]
                ),
                "jev": _latency_stats(
                    [m.jev_latency_ms for m in snapshot]
                ),
                "approval_wait": _latency_stats(
                    [m.approval_wait_ms for m in snapshot]
                ),
                "persistence": _latency_stats(
                    [m.persistence_time_ms for m in snapshot]
                ),
                "tool_execution": _latency_stats(
                    [m.tool_execution_time_ms for m in snapshot]
                ),
            },
        }


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


def _percentile(sorted_data: list[float], pct: float) -> float:
    """Compute the *pct*-th percentile from pre-sorted data.

    Uses linear interpolation between the two nearest ranks.

    Args:
        sorted_data: A non-empty, ascending-sorted list of floats.
        pct: Percentile in ``[0, 100]``.

    Returns:
        The interpolated percentile value.
    """
    if not sorted_data:
        return 0.0
    k = (pct / 100.0) * (len(sorted_data) - 1)
    floor_idx = int(k)
    ceil_idx = min(floor_idx + 1, len(sorted_data) - 1)
    fraction = k - floor_idx
    return sorted_data[floor_idx] + fraction * (
        sorted_data[ceil_idx] - sorted_data[floor_idx]
    )
