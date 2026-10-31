# AURA Known Limitations & Boundary Analysis

As specified in §9 of the AURA Essential Engineering Specification, this document provides a rigorous architectural rationale and boundary analysis for each of the 9 inherent limitations of the AURA enforcement framework.

---

### 1. No Universal Prompt-Injection Detection
* **Limitation**: AURA does not guarantee universal or 100% detection of indirect, multimodal, or adversarial prompt injections embedded within untrusted external data.
* **Architectural Rationale**: Prompt injection is fundamentally an undecidable problem in natural language processing; instructions and data share the same semantic channel in Large Language Models.
* **Mitigations & Boundaries**:
  - AURA treats prompt-injection detection as defense-in-depth, not the primary security boundary.
  - Primary boundary: **Structural Containment**. Even if an LLM is hijacked by an adversarial injection in a document, deterministic RBAC, confidential egress blocking, and tool parameter validation prevent unauthorized side-effects (e.g., emailing confidential data, arbitrary file reading).
  - JEV semantic analysis provides heuristic risk scoring but never overrides deterministic policy blocks.

---

### 2. No Guarantee of Detecting Every Encoded or Transformed Secret
* **Limitation**: Secrets that have been steganographically encoded, base64/rot13-transformed, obfuscated, or split across multiple variables may bypass heuristic regex scrubbing.
* **Architectural Rationale**: Deterministic string sanitizers rely on known patterns (e.g., standard API token prefixes, password fields, entropy thresholds). Arbitrary mathematical or semantic transformations cannot be exhaustively parsed without full semantic decompilation.
* **Mitigations & Boundaries**:
  - The audit logger applies regular expressions targeting common tokens (Bearer, AWS keys, generic high-entropy API secrets).
  - Taint tracking tracks data lineage at the resource level, preventing entire payloads from reaching egress points regardless of internal encoding.

---

### 3. Taint Tracking May Overblock (Coarse-Grained Lineage)
* **Limitation**: Reading a confidential resource taints the entire `RunContext` for subsequent egress actions in that run.
* **Architectural Rationale**: Fine-grained, variable-level information flow tracking inside a neural network's latent weights is mathematically impossible at runtime. AURA therefore uses coarse-grained run-level taint propagation.
* **Mitigations & Boundaries**:
  - Agents performing multi-step workflows that require both confidential reads and external egress must either partition workflows across distinct runs/agents or obtain explicit human approval for unblocking.
  - This deliberate design bias prioritizes data confidentiality over workflow convenience (security-first fail-closed model).

---

### 4. Only Operations Routed Through AURA Adapters Are Protected
* **Limitation**: Any process, third-party library, or agent code that attempts out-of-band I/O (e.g., native `open()`, raw `socket`, unmediated `subprocess`) bypasses AURA enforcement.
* **Architectural Rationale**: AURA operates as a software security kernel and gateway in user space. It does not replace OS-level cgroups, seccomp filters, or container boundaries.
* **Mitigations & Boundaries**:
  - Agent loops must only receive the `AuraGateway` interface or isolated tool action schemas. Tool adapters are kept private and instantiated strictly within the gateway.
  - In production deployments, AURA should be deployed alongside container isolation (Docker/gVisor) and OS-level network namespaces preventing unmediated outbound egress.

---

### 5. No Arbitrary-Code Sandbox
* **Limitation**: AURA provides typed adapters for structured operations (`read_file`, `send_email`, `run_query`, `call_api`). It does not provide a general-purpose arbitrary code execution sandbox (e.g., arbitrary Python execution or shell command execution).
* **Architectural Rationale**: General-purpose arbitrary code execution presents unbounded attack surfaces that undermine deterministic authorization and parameter validation.
* **Mitigations & Boundaries**:
  - All agent capabilities must be decomposed into typed, parameterized tool adapters with explicit schemas.
  - If dynamic execution is required in the future, it must be delegated to an isolated external container runtime governed by an AURA adapter with pre-declared constraints.

---

### 6. Approval is Simulated Unless Real Authentication is Configured
* **Limitation**: In the default single-process reference configuration, the resolver's identity (`resolved_by`) is passed as a string identifier rather than verified against a hardware token or enterprise SSO identity provider.
* **Architectural Rationale**: Single-process core libraries avoid hard dependencies on specific identity providers (Okta, Azure AD, WebAuthn) to remain portable and lightweight.
* **Mitigations & Boundaries**:
  - AURA enforces separation of duties: the requesting agent identity cannot match `resolved_by`.
  - In production, the `ApprovalManager` must be wrapped with an enterprise identity proxy that validates JWT/mTLS claims before invoking `resolve_approval()`.

---

### 7. Hash Chain is Tamper-Evident, Not Inherently Tamper-Proof
* **Limitation**: An attacker with full write access to the underlying SQLite database file can rewrite the entire database and recompute a valid cryptographic hash chain from genesis.
* **Architectural Rationale**: Cryptographic hash chaining ensures *tamper-evidence*—any modification, deletion, or reordering of records without re-hashing will immediately fail `verify_hash_chain()`. However, local storage alone cannot prevent an attacker with root file-system access from recalculating the whole chain.
* **Mitigations & Boundaries**:
  - AURA provides JSONL streaming export (`Store.export_jsonl()`) designed to ship audit entries continuously to external, immutable write-once-read-many (WORM) storage (e.g., AWS S3 Glacier with Object Lock, remote SIEM).
  - Periodic hash chain anchor signatures should be committed to external key-value ledgers.

---

### 8. Exactly-Once External Side Effects Are Not Guaranteed
* **Limitation**: While AURA enforces exactly-once gateway claims via caller-scoped idempotency, downstream third-party network services (e.g., remote mail servers, HTTP APIs) may experience partial failures after tool dispatch.
* **Architectural Rationale**: Distributed systems physical limitation (the Two Generals' Problem). If an adapter sends an email, but the network connection drops before AURA records the completion status, a retry may duplicate the external side effect.
* **Mitigations & Boundaries**:
  - Idempotency keys are claimed *prior* to adapter execution in status `in_progress`.
  - Adapters interfacing with external APIs must pass upstream idempotency tokens (e.g., Stripe/AWS `ClientRequestToken`) using the request's `idempotency_key`.

---

### 9. SQLite / Gateway Availability is Required (Fail-Closed Availability Trade-off)
* **Limitation**: If the local SQLite database becomes unavailable (disk full, hardware failure, unresolvable lock contention), the gateway completely halts all agent execution.
* **Architectural Rationale**: AURA enforces a strict *fail-closed* invariant. If the system cannot durably write an audit record or record an authorization decision, allowing execution would violate auditability and compliance.
* **Mitigations & Boundaries**:
  - High availability of the local storage is guaranteed through WAL mode, busy timeouts (5,000 ms), and bounded transaction scopes.
  - The architectural trade-off is deliberate: **Security and auditability strictly take precedence over availability.**

