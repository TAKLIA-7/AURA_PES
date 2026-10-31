"""
AURA Rate Limiter — In-memory sliding-window rate limiting with concurrency control.

Provides per-agent rate limiting (requests-per-window) and concurrency limiting
(max simultaneous in-flight operations). Thread-safe via :class:`threading.Lock`.

Design decisions
----------------
* **Sliding window**: stale timestamps are pruned on every ``check_rate_limit`` call
  so memory stays bounded.
* **No external dependencies**: uses :func:`time.time` for wall-clock timestamps
  and stdlib threading primitives.
* **Fail-closed**: if an agent is not found in the registry the rate check blocks.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from aura.models import AgentConfig, Decision, RiskLevel, RuleResult


# ── Default constants ──────────────────────────
_DEFAULT_WINDOW_SECONDS: int = 60
_DEFAULT_MAX_REQUESTS: int = 100
_DEFAULT_MAX_CONCURRENT: int = 10


class RateLimiter:
    """Sliding-window rate limiter with per-agent concurrency control.

    Parameters
    ----------
    global_config:
        Global rate-limit settings.  Recognised keys:

        * ``"window_seconds"`` — sliding window width (default 60).
        * ``"max_requests"`` — global per-agent request cap (default 100).
        * ``"max_concurrent"`` — global per-agent concurrency cap (default 10).

    agents_config:
        Mapping of ``agent_id → AgentConfig``.  Each agent may override limits
        via ``AgentConfig.rate_limits`` with the keys ``"max_requests"`` and
        ``"max_concurrent"``.
    """

    _RULE_ID = "rate_limit_check"
    _RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    _CONCURRENCY_EXCEEDED = "CONCURRENCY_EXCEEDED"
    _RATE_LIMIT_OK = "RATE_LIMIT_OK"
    _AGENT_NOT_FOUND = "AGENT_NOT_FOUND"

    def __init__(
        self,
        global_config: dict[str, Any],
        agents_config: dict[str, AgentConfig],
    ) -> None:
        if not isinstance(global_config, dict):
            raise TypeError(
                f"global_config must be a dict, got {type(global_config).__name__}"
            )
        if not isinstance(agents_config, dict):
            raise TypeError(
                f"agents_config must be a dict[str, AgentConfig], got {type(agents_config).__name__}"
            )

        self._global_window: int = int(
            global_config.get("window_seconds", _DEFAULT_WINDOW_SECONDS)
        )
        self._global_max_requests: int = int(
            global_config.get("max_requests", _DEFAULT_MAX_REQUESTS)
        )
        self._global_max_concurrent: int = int(
            global_config.get("max_concurrent", _DEFAULT_MAX_CONCURRENT)
        )

        self._agents: dict[str, AgentConfig] = dict(agents_config)

        # Per-agent sliding window of request timestamps
        self._windows: dict[str, list[float]] = {}
        # Per-agent current concurrency count
        self._concurrent: dict[str, int] = {}

        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────

    def check_rate_limit(self, agent_id: str) -> RuleResult:
        """Check whether *agent_id* is within rate and concurrency limits.

        Returns
        -------
        RuleResult
            ``Decision.BLOCK`` / ``RATE_LIMIT_EXCEEDED`` or
            ``CONCURRENCY_EXCEEDED`` when a limit is hit.
            ``Decision.ALLOW`` / ``RATE_LIMIT_OK`` otherwise.
        """
        agent = self._agents.get(agent_id)
        if agent is None:
            return RuleResult(
                rule_id=self._RULE_ID,
                decision=Decision.BLOCK,
                reason_code=self._AGENT_NOT_FOUND,
                risk_level=RiskLevel.HIGH,
                metadata={"agent_id": agent_id},
            )

        max_requests = self._resolve_max_requests(agent)
        max_concurrent = self._resolve_max_concurrent(agent)
        now = time.time()

        with self._lock:
            # ── Prune stale entries ──────────
            window = self._windows.get(agent_id, [])
            cutoff = now - self._global_window
            window = [ts for ts in window if ts > cutoff]
            self._windows[agent_id] = window

            # ── Rate check ───────────────────
            if len(window) >= max_requests:
                return RuleResult(
                    rule_id=self._RULE_ID,
                    decision=Decision.BLOCK,
                    reason_code=self._RATE_LIMIT_EXCEEDED,
                    risk_level=RiskLevel.MEDIUM,
                    metadata={
                        "agent_id": agent_id,
                        "current_count": len(window),
                        "max_requests": max_requests,
                        "window_seconds": self._global_window,
                    },
                )

            # ── Concurrency check ────────────
            current_concurrent = self._concurrent.get(agent_id, 0)
            if current_concurrent >= max_concurrent:
                return RuleResult(
                    rule_id=self._RULE_ID,
                    decision=Decision.BLOCK,
                    reason_code=self._CONCURRENCY_EXCEEDED,
                    risk_level=RiskLevel.MEDIUM,
                    metadata={
                        "agent_id": agent_id,
                        "current_concurrent": current_concurrent,
                        "max_concurrent": max_concurrent,
                    },
                )

        return RuleResult(
            rule_id=self._RULE_ID,
            decision=Decision.ALLOW,
            reason_code=self._RATE_LIMIT_OK,
            risk_level=RiskLevel.LOW,
            metadata={
                "agent_id": agent_id,
                "current_count": len(window),
                "max_requests": max_requests,
                "current_concurrent": current_concurrent,
                "max_concurrent": max_concurrent,
            },
        )

    def acquire(self, agent_id: str) -> bool:
        """Try to acquire a concurrency slot for *agent_id*.

        Returns
        -------
        bool
            ``True`` if a slot was acquired, ``False`` if the agent is at its
            concurrency limit.
        """
        agent = self._agents.get(agent_id)
        max_concurrent = (
            self._resolve_max_concurrent(agent) if agent else self._global_max_concurrent
        )

        with self._lock:
            current = self._concurrent.get(agent_id, 0)
            if current >= max_concurrent:
                return False
            self._concurrent[agent_id] = current + 1
            return True

    def release(self, agent_id: str) -> None:
        """Release a concurrency slot for *agent_id*.

        Safe to call even if no slot is held — the count will not go below zero.
        """
        with self._lock:
            current = self._concurrent.get(agent_id, 0)
            self._concurrent[agent_id] = max(0, current - 1)

    def record_request(self, agent_id: str) -> None:
        """Record a request timestamp in the sliding window for *agent_id*."""
        now = time.time()
        with self._lock:
            if agent_id not in self._windows:
                self._windows[agent_id] = []
            self._windows[agent_id].append(now)

    # ── Private helpers ─────────────────────────

    def _resolve_max_requests(self, agent: AgentConfig) -> int:
        """Return the effective max-requests limit for *agent*.

        Agent-level overrides (``AgentConfig.rate_limits["max_requests"]``)
        take precedence over the global default.
        """
        return int(agent.rate_limits.get("max_requests", self._global_max_requests))

    def _resolve_max_concurrent(self, agent: AgentConfig) -> int:
        """Return the effective max-concurrent limit for *agent*.

        Agent-level overrides (``AgentConfig.rate_limits["max_concurrent"]``)
        take precedence over the global default.
        """
        return int(agent.rate_limits.get("max_concurrent", self._global_max_concurrent))
