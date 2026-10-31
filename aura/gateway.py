"""AURA Gateway — ``AURA.handle()`` entry point.

Stub for Phase 1.  Full implementation in Phase 2.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aura.models import AuraRequest, AuraResult, RunContext


class AuraGateway:
    """Central enforcement gateway — all protected calls pass through here.

    Phase 1 stub: the gateway will be wired in Phase 2.
    """

    def handle(self, request: AuraRequest, run_ctx: RunContext) -> AuraResult:
        raise NotImplementedError("Gateway implementation is Phase 2")
