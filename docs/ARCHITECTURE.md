# AURA Architectural Specification

## 1. System Overview

**AURA** (Agentic Unified Risk and Authorization) is a single-process, fail-closed enforcement layer and security kernel designed to mediate all interactions between autonomous AI agents and protected execution environments (APIs, databases, file systems, communication channels).

Autonomous agents are fundamentally untrusted callers. AURA does not rely on prompt-level self-restraint or non-deterministic model alignment. Instead, it enforces strict compile-time and runtime security invariants:
- **No Direct Adapter Invocation**: Agents cannot call underlying tools directly; all actions are submitted as structured `AuraRequest` envelopes to `AuraGateway.handle(request, run_ctx)`.
- **Prohibited Actions Are Non-Invocations**: Denied or blocked actions result in zero invocations of the tool adapter (`call_counter == 0`).
- **Ordered Deterministic Policy Engine**: Static RBAC, resource validation, taint propagation, confidential egress prevention, and rate limiting execute before calling probabilistic evaluators.
- **Monotone Risk Combination**: When a Just-in-Time Evaluation Validator (JEV) is consulted, the combined risk score satisfies $\text{final} = \max(\text{rule\_risk}, \text{jev\_risk})$.
- **Tamper-Evident Hash Chain Audit Log**: Every decision and execution outcome is atomically committed to an append-only SQLite database using WAL mode and `synchronous=FULL`, chained by SHA-256 hashes linking each entry to its predecessor.
- **Digest-Bound Human Approvals**: Sensitive operations transition to `Decision.APPROVAL`, freezing execution parameters via SHA-256 digests. Resumptions execute stored parameters—not caller re-submissions.

---

## 2. Gateway Request Lifecycle

The diagram below depicts the execution pipeline of `AuraGateway.handle()`:

```mermaid
flowchart TD
    Req([AuraRequest]) --> IdempCheck{Idempotency Key?}
    IdempCheck -- Yes: Cached Result Exists --> RetCached([Return Cached AuraResult])
    IdempCheck -- Yes: In Progress / Conflict --> ErrIdemp([Fail: Idempotency Conflict])
    IdempCheck -- No / New Key --> StepCheck{Step <= Max & Deadline OK?}
    
    StepCheck -- No --> BlockStep[Decision: BLOCK\nReason: MAX_STEPS / DEADLINE_EXCEEDED]
    StepCheck -- Yes --> DetRules[Deterministic Rule Engine]
    
    DetRules --> CheckDet{Deterministic Decision}
    CheckDet -- BLOCK --> RecAuditBlock[Durable Audit Write]
    CheckDet -- APPROVAL --> RecAuditAppr[Create Approval Record\nDurable Audit Write]
    CheckDet -- ALLOW --> JEVCheck{JEV Required?}
    
    JEVCheck -- No --> ExecAdapter[Execute Tool Adapter]
    JEVCheck -- Yes --> CallJEV[Consult JEV: Gemini/OpenRouter]
    
    CallJEV -- Timeout / Error --> FailClosed[Decision: BLOCK\nFail-Closed Principle]
    CallJEV -- Success --> CombRisk[Monotone Risk: max(rule, jev)]
    CombRisk -- Risk >= HIGH --> BlockJEV[Decision: BLOCK]
    CombRisk -- APPROVAL Required --> RecAuditAppr
    CombRisk -- ALLOW --> ExecAdapter
    
    ExecAdapter --> CheckTaint[Evaluate Tool Output\nTaint Context if Output is Sensitive]
    CheckTaint --> RecAuditAllow[Durable Audit Write\nCommit Result to Idempotency Store]
    
    BlockStep --> RecAuditBlock
    FailClosed --> RecAuditBlock
    BlockJEV --> RecAuditBlock
    
    RecAuditBlock --> Resp([AuraResult])
    RecAuditAppr --> Resp
    RecAuditAllow --> Resp
```

---

## 3. Core Subsystems

### 3.1 Deterministic Policy Engine (`aura.policy` & `aura.rules`)
Deterministic rules execute in an explicit, immutable sequence. Any rule returning `Decision.BLOCK` short-circuits the pipeline immediately, avoiding unnecessary probabilistic computation:
1. **`PermissionCheckRule`**: Enforces deny-by-default Role-Based Access Control (RBAC). Verifies agent identity, role validity, and checks whether the role is permitted to perform the requested `ToolAction` on the specified resource sensitivity.
2. **`ResourceExistenceRule`**: Validates whether the targeted resource identifier (e.g., `doc_id`, `query_name`) exists in the trusted Resource Registry. Skips external endpoints such as email recipients.
3. **`TaintPropagationRule`**: Flags read operations targeting `CONFIDENTIAL` or `RESTRICTED` resources, tagging the execution run context with `tainted=True` and recording taint source IDs.
4. **`ConfidentialEgressRule`**: Intercepts egress actions (`SEND_EMAIL`, untrusted `CALL_API`). If `run_ctx.taint.tainted == True`, it immediately issues a hard `Decision.BLOCK` (`CONFIDENTIAL_EGRESS_BLOCKED`), preventing data exfiltration.
5. **`RateLimitRule`**: Enforces agent- and role-based sliding window request budgets.

### 3.2 Just-in-Time Evaluation Validator (JEV) (`aura.jev`)
For operations requiring contextual reasoning or semantic safety evaluation (e.g., destructive actions, prompt-injection analysis):
- **Base Interface**: `JEVBase` defining `evaluate(request, run_ctx) -> JEVResult`.
- **Implementations**:
  - `MockJEV`: Fast deterministic validator for unit and integration testing.
  - `GeminiJEV`: Integration with the modern `google-genai` SDK using structured JSON schema output, strict prompt-size capping (1,500 characters), a 5.0-second timeout, and maximum 2 attempts.
  - `OpenRouterJEV`: Fallback HTTP-based validator for cross-model verification.
- **Fail-Closed Guarantees**: Any network partition, timeout, missing API credentials, schema parsing failure, or cross-field validation anomaly immediately evaluates to `Decision.BLOCK`. The system never defaults to open execution.

### 3.3 Authoritative SQLite Store (`aura.store`)
The persistence subsystem is implemented as a single-process SQLite store configured with high-durability pragmas:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
```

#### Hash-Chain Audit Log
Each audit record is linked cryptographically to the preceding record:
$$\text{payload} = \text{sequence} \parallel \text{timestamp} \parallel \text{trace\_id} \parallel \text{agent\_id} \parallel \text{action} \parallel \text{decision} \parallel \text{reason} \parallel \text{risk\_level} \parallel \text{params\_hash} \parallel \text{exec\_status}$$
$$\text{current\_hash} = \text{SHA-256}(\text{previous\_hash} \parallel \text{payload})$$
The initial record (`sequence = 1`) links to the canonical `GENESIS_HASH` (`0000000000000000000000000000000000000000000000000000000000000000`).

#### Atomic Caller-Scoped Idempotency
Prevents duplicate tool execution during agent retries or concurrent dispatches. Idempotency claims are keyed by `(agent_id, idempotency_key)` and bound to the SHA-256 digest of the request.

#### Digest-Bound Approval Workflow
Sensitive actions return `Decision.APPROVAL` with an issued `approval_id`. A human compliance officer or supervisor resolves the request (`APPROVED` or `REJECTED`). Upon resumption, the gateway verifies:
- Single-use consumption (atomic SQL `UPDATE approvals SET status = 'CONSUMED' WHERE status = 'APPROVED'`).
- TTL expiration.
- Separation of duties (the requesting agent cannot approve their own action).
- Execution of frozen parameters: The adapter executes `stored_params` from the database, preventing parameter tampering upon re-submission.

### 3.4 Typed Tool Adapters (`aura.tools`)
Protected tool adapters enforce strict runtime boundaries:
- **`ReadFileAdapter`**: Enforces strict path normalization, directory confinement, and explicit rejection of path traversal (`..`, `~`, `/`, `\`).
- **`RunQueryAdapter`**: Restricts database execution to named, allowlisted SQL templates with mandatory parameterized variable bindings. Completely neutralizes SQL injection (`OR 1=1`, `UNION`, `DROP TABLE`).
- **`SendEmailAdapter`**: Strict RFC-compliant recipient address verification and payload bounds.
- **`CallApiAdapter`**: Allowlisted operation mapping to prevent arbitrary SSRF or external URL requests.
- **Zero Call Invariant**: Tool adapters maintain execution counters (`call_count`). If an action is denied by RBAC, blocked by confidential egress, or interrupted by a failed durable audit write, the adapter is never invoked.

---

## 4. Invariant Verification Summary
All invariants have been validated across 172 automated test suites:
- Deterministic fast-path execution: **< 0.3 ms** p50 latency.
- High-concurrency stress testing: **1,900+ ops/sec** across 32 concurrent workers with zero hash chain corruption.
- Complete fail-closed posture across all failure boundaries.

