# AURA Platform Architecture Specification

## 1. System Overview
**AURA** (Agent Unified Risk & Authorization) is a zero-trust execution enforcement and authorization gateway for autonomous AI agents. Rather than allowing agents to invoke tool callables directly or manage private credentials, AURA acts as an in-process, authoritative enforcement boundary.

```
+-------------------------------------------------------------------+
|                        User / Application                         |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|               Multi-Agent Orchestration (LangGraph)               |
|  * Supervisor Node                                                |
|  * Specialist Agents (Research, SQL, Email, Admin)                |
|  * Automatic function execution DISABLED                          |
|  * Agents propose ToolRequest schemas, NOT tool execution         |
+-------------------------------------------------------------------+
                                  |
                      ToolRequest proposals only
                                  v
+===================================================================+
|                    AURA ENFORCEMENT GATEWAY                       |
|                                                                   |
|  1. Authenticate Agent Identity & Inject Trusted RunContext       |
|  2. Agent RBAC Permission & Resource Scope Check                  |
|  3. Sliding-Window Rate Limiting & Concurrency Control            |
|  4. Deterministic Policy Rules (6 Focused Stateless Rules)        |
|  5. Ambiguity Evaluation via JEV (OpenRouter / Gemini / Mock)     |
|  6. Monotone Policy Combination (final = max(rule, jev))          |
|  7. Human-in-the-Loop Approval Workflow (Canonical Digest Bound)  |
|  8. Caller-Scoped Idempotency & Atomic Execution Claims           |
|  9. Private Typed Tool Execution (Zero direct agent access)       |
| 10. Durable SQLite WAL Audit Log + SHA-256 Hash Chain              |
| 11. Ordered JSONL Export & High-Resolution Telemetry              |
+===================================================================+
                                  |
                       Actual GatewayResult
                                  v
+-------------------------------------------------------------------+
|                       Agent Synthesis Node                        |
|  * Base final answer STRICTLY on AURA GatewayResult               |
|  * Hallucination & False-Success Prevention (ResponseEvaluator)   |
+-------------------------------------------------------------------+
```

## 2. Core Non-Negotiable Invariants
1. **Zero Direct Execution**: AI agents never hold references to tool callables or credentials.
2. **Deterministic Supremacy**: Deterministic rule BLOCK decisions are final and cannot be overturned by LLMs or JEV.
3. **Monotonic Risk Escalation**: JEV may elevate risk levels (ALLOW -> APPROVAL -> BLOCK), but can never lower them.
4. **Digest-Bound Approvals**: Approvals are bound to the SHA-256 canonical digest of exact parameters. Parameter mutation invalidates the approval.
5. **Fail-Closed Guarantee**: Any timeout, network fault, malformed output, or persistent error immediately defaults to BLOCK.

## 3. Component Hierarchy
* `aura.gateway.AuraGateway`: Authoritative entry point (`handle()` and `handle_async()`).
* `aura.policy.PolicyEngine`: Loads YAML rules and calculates monotonic decision combinations.
* `aura.rules`: Stateless deterministic evaluation rules.
* `aura.jev`: LLM-based Judgment and Evaluation Component (Gemini, OpenRouter, Mock).
* `aura.store.AuraStore`: SQLite persistence in WAL mode with full synchrony.
* `aura.audit.AuditLogger`: Tamper-evident cryptographic hash chain.
* `aura.approval.ApprovalManager`: Persistent human sign-off lifecycle.
* `aura.tools.ToolRegistry`: Private typed tool implementations with call counters.
* `aura.agent.AuraMultiAgentSystem`: LangGraph multi-agent loop with switchable AI models.

