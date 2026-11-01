# AURA Cryptographic Audit Schema & Hash Chain

## 1. Authoritative SQLite WAL Schema
The SQLite persistence layer serves as the single source of truth. It is configured with `journal_mode=WAL` and `synchronous=FULL`.

### `audit_events` Table
```sql
CREATE TABLE IF NOT EXISTS audit_events (
    event_id            TEXT PRIMARY KEY,
    request_id          TEXT NOT NULL,
    trace_id            TEXT NOT NULL,
    timestamp           TEXT NOT NULL,
    sequence_number     INTEGER NOT NULL UNIQUE,
    prev_hash           TEXT NOT NULL,
    this_hash           TEXT NOT NULL,
    hash_algorithm      TEXT NOT NULL DEFAULT 'sha256',
    event_json          TEXT NOT NULL
);
```

### `idempotency` & `execution_claims` Tables
```sql
CREATE TABLE IF NOT EXISTS idempotency (
    idem_key            TEXT PRIMARY KEY,
    digest              TEXT NOT NULL,
    status              TEXT NOT NULL,   -- PENDING, CLAIMED, COMPLETED, FAILED, UNKNOWN
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    result_summary      TEXT
);

CREATE TABLE IF NOT EXISTS execution_claims (
    idem_key            TEXT PRIMARY KEY,
    request_id          TEXT NOT NULL,
    claimed_at          TEXT NOT NULL,
    FOREIGN KEY (idem_key) REFERENCES idempotency(idem_key)
);
```

## 2. Cryptographic SHA-256 Hash Chain
Every audit event contains:
* `sequence_number`: Monotonically increasing integer ($1, 2, 3, \dots$).
* `prev_hash`: The `this_hash` of the immediately preceding event (`"0"*64` for sequence 1).
* `this_hash`: $\text{SHA-256}(\text{canonical\_json}(\text{event}))$.

### Integrity Verification Algorithm
The verification procedure performs:
1. Re-computes $\text{SHA-256}$ over each event's canonical JSON serialization.
2. Asserts that calculated hash matches `this_hash`.
3. Asserts that `event[i].prev_hash == event[i-1].this_hash`.
4. Asserts that sequence numbers have no gaps or reorderings.
Any mutation, insertion, deletion, or truncation causes `AuditLogger.verify_integrity()` to fail and report the exact compromised sequence number.

