# AURA Security Invariants Matrix

This document defines the formal security invariants enforced by the AURA gateway kernel, mapping each invariant to its operational defense mechanism, threat vector, and automated test suite.

---

## 1. Core Invariants Matrix

| Invariant ID | Security Invariant Description | Threat Vector Prevented | Enforcement Layer | Primary Test Suite |
| :--- | :--- | :--- | :--- | :--- |
| **INV-01** | **Zero-Invocation on Block**<br>Prohibited, blocked, or unapproved actions must never trigger the underlying tool adapter. | Unauthorized data access, unauthorized state mutation, unintended external side effects. | `AuraGateway.handle()` pipeline gating; adapter execution occurs only when `decision == Decision.ALLOW`. | `tests/unit/test_gateway.py`<br>`tests/security/test_adversarial_matrix.py` |
| **INV-02** | **Fail-Closed Default**<br>Any unhandled exception, network timeout, rate limit failure, parser failure, or database write error must immediately resolve to `Decision.BLOCK`. | Fail-open bypass during transient dependency outages, network partition bypass, JEV crash exploitation. | Gateway try/catch blocks; SQLite durability check; JEV exception handlers. | `tests/unit/test_gateway.py::TestScenario5FailClosed`<br>`tests/failure/test_crash_recovery.py` |
| **INV-03** | **Monotone Risk Combination**<br>Combined operational risk satisfies $\text{final} = \max(\text{rule\_risk}, \text{jev\_risk})$. JEV cannot reduce or downgrade static rule risk. | Model jailbreaks or sycophancy coercing a secondary evaluator to permit an unsafe action. | `PolicyEngine.combine_with_jev()` | `tests/unit/test_policy.py::TestCombineWithJev` |
| **INV-04** | **Tamper-Evident Hash Chain**<br>Audit records form an unbroken SHA-256 hash chain rooted at `GENESIS_HASH`. Any retroactive alteration, insertion, or row deletion invalidates verification. | Audit record tampering, cover-up of malicious agent activity, rogue insider log scrubbing. | `Store.append_audit_entry()` and `Store.verify_hash_chain()` | `tests/unit/test_store.py::TestAuditHashChain`<br>`tests/security/test_adversarial_matrix.py` |
| **INV-05** | **Caller-Scoped Idempotency**<br>Idempotency keys are strictly bound to `(agent_id, idempotency_key)` and the SHA-256 request digest. Different agents or modified payloads cannot hijack or replay keys. | Idempotency key squatting, replay attacks, cross-agent result snooping, parameter modification during retries. | `Store.claim_idempotency_key()` and `idempotency_store` table uniqueness constraints. | `tests/unit/test_store.py::TestIdempotency`<br>`tests/security/test_concurrency.py` |
| **INV-06** | **Digest-Bound Human Approval**<br>Human approvals bind immutably to the original request's parameters via SHA-256 digest. Resumption executes database-stored parameters, not caller resubmissions. | Parameter tampering between approval and execution (Time-of-Check to Time-of-Use / TOCTOU). | `ApprovalManager.consume_approval()` and `Store.save_approval()` | `tests/unit/test_approval.py`<br>`tests/security/test_adversarial_matrix.py` |
| **INV-07** | **Separation of Duties**<br>An agent cannot approve its own pending approval requests under any circumstance. | Privilege escalation where compromised autonomous agents self-authorize sensitive operations. | `ApprovalManager.resolve_approval()` identity assertion (`agent_id != resolved_by`). | `tests/unit/test_approval.py::TestApprovalManager::test_self_approval_prevented` |
| **INV-08** | **Single-Use Approval Token**<br>An approved token can only be consumed once. Concurrent or duplicate execution attempts fail atomically. | Replay attacks, double execution of approved financial or sensitive operational actions. | SQLite atomic conditional update: `UPDATE approvals SET status = 'CONSUMED' WHERE approval_id = ? AND status = 'APPROVED'`. | `tests/security/test_concurrency.py::TestConcurrencyAndRaceConditions::test_concurrent_approval_consumption_single_winner` |
| **INV-09** | **Confidential Taint Propagation**<br>Reading a `CONFIDENTIAL` or `RESTRICTED` resource taints the run context. Tainted contexts cannot execute external egress tools (`SEND_EMAIL`, external `CALL_API`). | Data exfiltration via indirect prompt injection or unintended email/API communication. | `TaintPropagationRule`, `ConfidentialEgressRule`, and `AuraGateway` post-read taint scanner. | `tests/unit/test_gateway.py::TestScenario2ConfidentialEgress`<br>`tests/unit/test_rules.py` |
| **INV-10** | **Path Traversal Containment**<br>File read actions reject relative paths containing `..`, leading slashes, path separators, or symbols attempting directory breakout. | Arbitrary local file read (LFI), host configuration disclosure, credential file access (`/etc/passwd`, `.env`). | `ReadFileAdapter.execute()` validation and base directory normalization. | `tests/unit/test_tools.py::TestReadFileAdapter`<br>`tests/security/test_adversarial_matrix.py` |
| **INV-11** | **SQL Injection Neutralization**<br>Database queries are limited to pre-registered allowlisted query templates with parameterized bindings. Dynamic raw SQL is completely rejected. | Direct or second-order SQL injection, database table dropping, unauthorized data dumps (`' OR 1=1 --`). | `RunQueryAdapter.execute()` allowlist matching and parameterized SQL statement preparation. | `tests/unit/test_tools.py::TestRunQueryAdapter`<br>`tests/security/test_adversarial_matrix.py` |
| **INV-12** | **Bounded Agent Execution**<br>Agent run loops are bounded by strict step limits ($\le 8$ steps) and real-time execution deadlines ($\le 60$ seconds). | Infinite loops, denial of service (DoS), runaway billing caused by adversarial hallucinations or tool ping-pong. | `AuraGateway.handle()` step count and deadline checks; `AgentLoop.run()`. | `tests/unit/test_agent.py`<br>`tests/unit/test_gateway.py::TestBoundedExecution` |
| **INV-13** | **Credential & Secret Redaction**<br>Audit entries scrub and mask sensitive credentials, API keys, passwords, and bearer tokens before persistence. | Leakage of API tokens and passwords in system audit logs and compliance exports. | `AuditLogger._sanitize_summary()` regex sanitization pipeline. | `tests/unit/test_audit.py::TestSanitizeSummary` |

---

## 2. Test Execution Verification

All 13 security invariants are verified on every test run:
- Total Automated Test Cases: **172**
- Security & Adversarial Test Suites:
  - `tests/security/test_adversarial_matrix.py` (8 focused attack scenarios)
  - `tests/security/test_concurrency.py` (Race condition and double-spend mitigations)
  - `tests/failure/test_crash_recovery.py` (Crash resilience, durability failures, SQLite WAL integrity)
- Current Test Status: **100% Passing**.

