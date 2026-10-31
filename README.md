# AURA — AI-Agent Security & Execution-Enforcement Layer

AURA controls what AI agents can access and execute. Agents may propose tool
calls, but **AURA makes the authorization decision and executes approved
actions**.

Every protected tool call must pass through `AURA.handle(request, run_ctx)`.

## Quick Start

```bash
pip install -e ".[dev]"
pytest
```

## Architecture

- **Gateway** — `AURA.handle()`: single entry-point for all protected operations.
- **RBAC** — agent identity, role, and permission enforcement.
- **Policy Engine** — ordered deterministic rules with monotone risk combination.
- **JEV** — Judgement-Evaluation-Verification: LLM-backed ambiguity resolver (Mock → Gemini → OpenRouter).
- **Tool Adapters** — narrow typed adapters: `read_file`, `send_email`, `run_query`, `call_api`.
- **Resource Registry** — trusted source for resource existence and sensitivity.
- **Audit** — tamper-evident hash-chain audit trail in SQLite with JSONL export.
- **Approval** — digest-bound, TTL-enforced, replay-safe approval workflow.

## Known Limitations

- No universal prompt-injection detection.
- No guarantee of detecting every encoded/transformed secret.
- Taint tracking may overblock.
- Only operations routed through AURA adapters are protected.
- No arbitrary-code sandbox.
- Approval is simulated unless real authentication is configured.
- Hash chain is tamper-evident, not inherently tamper-proof.
- Exactly-once external side effects are not guaranteed.
- SQLite/gateway availability is required; protected execution stops if
  required checks or durable recording fail.
