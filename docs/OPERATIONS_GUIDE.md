# AURA Operations & Deployment Guide

This guide provides operational instructions for deploying, configuring, auditing, and benchmarking the AURA enforcement gateway.

---

## 1. System Requirements & Setup

### Requirements
- **Python**: 3.10 to 3.14+
- **Database**: SQLite 3.35+ (standard with Python standard library `sqlite3`)
- **Dependencies**: `pydantic>=2.0`, `pyyaml>=6.0`, `httpx>=0.27`
- **Optional**: `google-genai>=2.0` (for live Gemini JEV evaluation)

### Installation
From the root directory of the AURA project:
```bash
# Editable install
pip install -e .

# Verify installation and test suite
python -m pytest tests/ -v
```

---

## 2. Configuration Management

AURA configurations reside in YAML files within the `config/` directory.

### 2.1 Agent Registry (`config/agents.yaml`)
Defines registered agents and their assigned roles:
```yaml
agents:
  admin_agent:
    role: admin
    description: "System administration and maintenance agent"
  analyst_agent:
    role: analyst
    description: "Data analysis agent with internal query and read access"
  reader_agent:
    role: reader
    description: "Read-only agent for public documentation"
  mailer_agent:
    role: mailer
    description: "Outbound communication agent"
```

### 2.2 Resource Registry (`config/resources.yaml`)
Categorizes system resources and their data sensitivity classification (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`):
```yaml
resources:
  "public/readme":
    type: document
    classification: PUBLIC
    path: "docs/readme.txt"
  "internal/reports/q3":
    type: document
    classification: INTERNAL
    path: "reports/q3_summary.txt"
  "confidential/customer_financials":
    type: document
    classification: CONFIDENTIAL
    path: "secure/financials.csv"
  "query_active_users":
    type: database_query
    classification: INTERNAL
  "query_executive_payroll":
    type: database_query
    classification: RESTRICTED
```

### 2.3 Policy & Rate Limits (`config/policy.yaml`)
Defines RBAC permission matrix, rate limits, and approval policies:
```yaml
roles:
  admin:
    permissions:
      - action: READ_FILE
        sensitivity: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
      - action: RUN_QUERY
        sensitivity: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
      - action: SEND_EMAIL
      - action: CALL_API
  analyst:
    permissions:
      - action: READ_FILE
        sensitivity: ["PUBLIC", "INTERNAL"]
      - action: RUN_QUERY
        sensitivity: ["PUBLIC", "INTERNAL"]
  reader:
    permissions:
      - action: READ_FILE
        sensitivity: ["PUBLIC"]

rate_limits:
  default: 60
  roles:
    admin: 120
    analyst: 60
    reader: 30

approval_required_actions:
  - action: RUN_QUERY
    sensitivity: RESTRICTED
  - action: CALL_API
    target: "billing_service"
```

---

## 3. Command Line Interface (CLI)

The AURA CLI provides operational inspection, scenario demonstrations, and audit verification.

### 3.1 Running the Live Demonstration
Executes all 5 standard security scenarios (Fast-path read, Confidential Egress blocking, Digest-bound Approval, Prompt-injection neutralization, and Fail-closed JEV):
```bash
python -m aura.cli --demo
```

### 3.2 Verifying Audit Log Cryptographic Integrity
Validates that the SQLite hash chain is unbroken from genesis:
```bash
python -m aura.cli --verify-audit
```
*Output:*
```
[Audit Verification]
  Database : aura.db
  Verified : 100% Intact
  Entries  : 42
  Status   : OK
```

### 3.3 Exporting Audit Logs to JSONL
Streams immutable audit entries for external SIEM or WORM storage ingestion:
```bash
python -m aura.cli --export-jsonl audit_export.jsonl
```

### 3.4 Running the Multi-Agent Orchestration CLI
Renders the Rich terminal visual interface, inspecting agent identities, tool assignments, collaborative workflows, and real-time security blocks:
```bash
python -m aura.cli --multi-agent
```

### 3.5 Running Live Autonomous Agents with Google Gemini
Executes an autonomous agent task powered by `gemini-2.5-flash` under AURA's strict manual tool dispatch:
```bash
python -m aura.cli --task "Read public/readme and summarize it"
```

### 3.6 Approving Pending Operations
Resolves an outstanding approval request by its ID:
```bash
python -m aura.cli --approve apr-a1b2c3d4 --user compliance_officer
```

---

## 4. Performance Benchmarking

AURA includes a concurrency benchmarking harness measuring throughput and latency percentiles (p50, p95, p99) under concurrent loads (1, 8, 32 threads):
```bash
python -m bench.benchmark
```
*Expected baseline performance:*
- Concurrency 1: > 3,000 ops/sec, p50 < 0.3 ms
- Concurrency 8: > 1,800 ops/sec, p50 < 4.0 ms
- Concurrency 32: > 1,800 ops/sec, p50 < 16.0 ms

---

## 5. Integrating with Live Models (Gemini & OpenRouter)

To activate live Just-in-Time Evaluation Validators in place of Mock JEV:

### Gemini JEV Setup
Set your Gemini API key in your environment:
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```
In your application bootstrap:
```python
from aura.gateway import AuraGateway
from aura.jev.gemini import GeminiJEV

gateway = AuraGateway.create_default()
gateway.jev = GeminiJEV(model="gemini-2.5-flash")
```

### OpenRouter JEV Setup
```bash
export OPENROUTER_API_KEY="your-openrouter-api-key"
```
In your bootstrap:
```python
from aura.gateway import AuraGateway
from aura.jev.openrouter import OpenRouterJEV

gateway = AuraGateway.create_default()
gateway.jev = OpenRouterJEV(model="anthropic/claude-3.5-sonnet")
```
*Note*: If API keys are missing, network partitions occur, or requests exceed the 5-second deadline, AURA's fail-closed security policy automatically blocks execution with `Decision.BLOCK`.

