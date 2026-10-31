"""AURA Persistent Store.

Stub for Phase 1.  SQLite WAL store will be implemented in Phase 3.
"""

from __future__ import annotations


class AuraStore:
    """SQLite-backed persistent store (Phase 3)."""

    def __init__(self, db_path: str = "aura.db") -> None:
        self.db_path = db_path
        raise NotImplementedError("AuraStore — Phase 3")
