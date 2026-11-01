# AURA Documented Limitations & Security Boundaries

In accordance with Section 24 of the AURA Engineering Specification, the following limitations are explicitly documented:

1. **No Universal Prompt-Injection Detection**: AURA does not claim to detect every conceivable adversarial prompt injection. Ingestion defenses rely on treating all retrieved document contents as untrusted data, maintaining run-level taint tracking, and strictly enforcing egress restrictions deterministically.
2. **Encrypted or Transformed Secrets**: AURA cannot guarantee detection of secrets that have been arbitrarily encrypted, steganographically encoded, or mathematically transformed prior to egress.
3. **Run-Level Taint Conservatism**: Taint tracking is conservative and applies to the entire execution context once confidential data has been accessed. This may occasionally over-block legitimate subsequent actions within the same run.
4. **Scope of Protection**: AURA protects only actions that transit through its registered typed tool adapters. Direct code execution or unmediated third-party network requests outside of AURA are out of scope.
5. **No Arbitrary-Code Execution Sandbox**: AURA does not execute arbitrary agent-generated code. Controlled execution is limited to pre-declared typed adapters with allowlisted queries and parameters.
6. **Simulated Approver Authentication in Development**: In development and demonstration configurations, approver secrets are validated using SHA-256 hashes. Production deployments must use `bcrypt` or `argon2id` key derivation.
7. **Hash Chains are Tamper-Evident, Not Tamper-Proof**: The SHA-256 hash chain makes unauthorized modifications immediately detectable. Protection against a compromised host superuser requires optional external anchoring of the chain head.
8. **Single-Process Persistence Dependency**: AURA depends on SQLite WAL availability. Distributed clustering or multi-datacenter consensus is explicitly deferred per the architecture constraints.
9. **Ambiguous Side Effects (UNKNOWN State)**: If an external side-effectful API times out ambiguously, AURA transitions the state to `UNKNOWN` and refuses automatic retry to prevent double execution.

