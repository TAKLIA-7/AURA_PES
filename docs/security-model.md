# AURA Security Model & Threat Defense

## 1. Threat Model & Mitigations

| Threat | Attack Vector | AURA Defense Mechanism | Verification Test |
|---|---|---|---|
| **Identity Spoofing** | Agent submits forged `agent_id` or claims `admin` role in context | Gateway overwrites role from trusted registry `config/agents.yaml` | `test_failure_agent_role_spoofing_prevented` |
| **Data Exfiltration** | Agent reads confidential file and emails external domain | Run-level taint tracking + destination allowlisting blocks action before JEV | `test_scenario_2_confidential_egress_blocked` |
| **Prompt Injection** | Ingested document instructs agent to execute harmful tools | Document content is untrusted; deterministic policy enforces egress bounds | `test_scenario_4_prompt_injection_prevented` |
| **SQL Injection** | Agent generates raw SQL or parameter injection syntax | Allowlisted named queries only; raw SQL queries are rejected | `test_failure_raw_sql_injection_rejected` |
| **Approval Replay** | Consumed approval token replayed for second execution | Atomic single-use state transition `PENDING -> CONSUMED` in SQLite transaction | `test_failure_approval_replay_rejected` |
| **Approval Mutation** | Agent modifies parameters after operator grants approval | Approval is bound to SHA-256 canonical digest; modified parameters fail digest check | `test_concurrency.py` |
| **Audit Log Tampering** | Attacker modifies or deletes rows in SQLite database | Tamper-evident SHA-256 hash chain verification fails on any modified/missing row | `test_failure_audit_tampering_detected` |
| **JEV Evasion** | LLM judge hallucinates or returns contradictory LOW risk | Cross-field Pydantic validation escalates contradictory findings to HIGH/BLOCK | `test_rules.py::test_jev_high_risk_escalates` |
| **JEV Outage** | Network timeout or provider API unavailability | Fail-closed guarantee returns BLOCK with `JEV_TIMEOUT` / `JEV_UNAVAILABLE` | `test_scenario_5_jev_timeout_fail_closed` |
| **Hallucinated Success**| Agent claims blocked or failed operation succeeded | `ResponseEvaluator` inspects narration against gateway result and flags false success | `test_response_evaluator_detects_false_success` |

## 2. Monotonic Risk Decision Matrix
Deterministic rules and JEV assessments are combined monotonically using:
$$\text{final\_risk} = \max(\text{rule\_risk}, \text{jev\_risk})$$

Decision combinations:
* `BLOCK + ANY` -> `BLOCK` (immediate and final)
* `APPROVAL + LOW/MEDIUM` -> `APPROVAL`
* `DEFER + HIGH/CRITICAL` -> `BLOCK`
* `DEFER + APPROVAL` -> `APPROVAL`
* `ALLOW + LOW` -> `ALLOW`

