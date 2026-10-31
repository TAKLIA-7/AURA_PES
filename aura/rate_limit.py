"""AURA Rate Limiting.

Provides per-agent and per-role sliding window rate limiting.
Thread-safe in-memory implementation.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any


class RateLimiter:
    """Sliding-window in-memory rate limiter.

    Tracks request timestamps within a sliding window (default 60 seconds).
    Limits can be configured per agent ID and per role, with a fallback default.
    """

    def __init__(
        self,
        default_limit: int = 60,
        role_limits: dict[str, int] | None = None,
        agent_limits: dict[str, int] | None = None,
        window_seconds: float = 60.0,
    ) -> None:
        self.default_limit = default_limit
        self.role_limits = role_limits or {}
        self.agent_limits = agent_limits or {}
        self.window_seconds = window_seconds

        self._lock = threading.Lock()
        self._agent_history: dict[str, list[float]] = defaultdict(list)
        self._role_history: dict[str, list[float]] = defaultdict(list)

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> RateLimiter:
        """Create a RateLimiter from a policy dict."""
        rate_cfg = config.get("rate_limits", {})
        return cls(
            default_limit=rate_cfg.get("default", 60),
            role_limits=rate_cfg.get("per_role", {}),
            agent_limits=rate_cfg.get("per_agent", {}),
            window_seconds=rate_cfg.get("window_seconds", 60.0),
        )

    def get_limit(self, agent_id: str, role: str) -> int:
        """Determine the effective request limit for an agent and role."""
        if agent_id in self.agent_limits:
            return self.agent_limits[agent_id]
        if role in self.role_limits:
            return self.role_limits[role]
        return self.default_limit

    def check_and_consume(
        self, agent_id: str, role: str, now: float | None = None
    ) -> tuple[bool, str]:
        """Check if request is allowed under rate limits and record timestamp if so.

        Returns (allowed, reason_detail).
        """
        current_time = time.time() if now is None else now
        cutoff = current_time - self.window_seconds
        limit = self.get_limit(agent_id, role)

        with self._lock:
            # Clean expired timestamps for agent
            agent_timestamps = [t for t in self._agent_history[agent_id] if t > cutoff]
            self._agent_history[agent_id] = agent_timestamps

            # Clean expired timestamps for role
            role_timestamps = [t for t in self._role_history[role] if t > cutoff]
            self._role_history[role] = role_timestamps

            if len(agent_timestamps) >= limit:
                return False, f"Agent '{agent_id}' exceeded limit of {limit} req/{self.window_seconds}s"

            # Check role-wide limit if defined
            role_limit = self.role_limits.get(role)
            if role_limit is not None and len(role_timestamps) >= role_limit:
                return False, f"Role '{role}' exceeded limit of {role_limit} req/{self.window_seconds}s"

            # Record consumption
            agent_timestamps.append(current_time)
            role_timestamps.append(current_time)
            return True, "OK"

    def reset(self) -> None:
        """Reset all rate limiter state (useful for test isolation)."""
        with self._lock:
            self._agent_history.clear()
            self._role_history.clear()
