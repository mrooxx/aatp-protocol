"""
aatp_core/storage.py — AATP SQLite Storage Backend

Tables:
- records:            All audit records (per-agent chain)
- sessions:           Session metadata
- chain_state:        Per-agent chain state (last hash, last sequence)
- reviews:            Auditor review records (independent chain per 7.8)
- review_chain_state: Per-auditor chain state

Design adopted from v0.1 implementation, adapted for v2 Pydantic models.
The full AuditRecord JSON is stored in the `data` column; indexed columns
are extracted for efficient querying without deserializing every row.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from .record import AuditRecord


class Storage:
    """SQLite storage for AATP records.

    Each agent has one chain. Sessions cross-cut the chain via session_id.
    Auditors have independent review chains (Invariant 6: agent ≠ auditor).
    """

    def __init__(self, db_path: str = "./aatp_records.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        """Create tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS records (
                record_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                agent_did TEXT NOT NULL,
                audit_point_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                previous_hash TEXT,
                data TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_records_session
                ON records(session_id, sequence_number);
            CREATE INDEX IF NOT EXISTS idx_records_agent
                ON records(agent_did, sequence_number);

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent_did TEXT NOT NULL,
                principal_did TEXT NOT NULL,
                purpose TEXT NOT NULL,
                mode TEXT NOT NULL,
                authorization_vc_hash TEXT,
                audit_language TEXT NOT NULL DEFAULT 'en',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                closed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS chain_state (
                agent_did TEXT PRIMARY KEY,
                last_record_hash TEXT NOT NULL,
                last_sequence_number INTEGER NOT NULL,
                total_records INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS reviews (
                review_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                auditor_did TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                previous_hash TEXT,
                data TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_reviews_session
                ON reviews(session_id);
            CREATE INDEX IF NOT EXISTS idx_reviews_auditor
                ON reviews(auditor_did);

            CREATE TABLE IF NOT EXISTS review_chain_state (
                auditor_did TEXT PRIMARY KEY,
                last_record_hash TEXT NOT NULL,
                last_sequence_number INTEGER NOT NULL
            );
        """)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Record operations
    # ------------------------------------------------------------------

    def save_record(self, record: AuditRecord) -> None:
        """Save a sealed audit record to storage."""
        self.conn.execute(
            """INSERT INTO records
               (record_id, session_id, sequence_number, agent_did,
                audit_point_type, timestamp, record_hash, previous_hash, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.header.record_id,
                record.header.session_id,
                record.chain.sequence_number,
                record.authorization.agent_did,
                record.header.audit_point_type.value,
                record.header.timestamp.isoformat(),
                record.chain.record_hash,
                record.chain.previous_hash,
                record.model_dump_json(),
            ),
        )
        self.conn.commit()

    def get_record(self, record_id: str) -> Optional[AuditRecord]:
        """Get a single record by ID."""
        row = self.conn.execute(
            "SELECT data FROM records WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row:
            return AuditRecord.model_validate_json(row["data"])
        return None

    def get_session_records(self, session_id: str) -> list[AuditRecord]:
        """Get all records for a session, ordered by sequence number."""
        rows = self.conn.execute(
            "SELECT data FROM records WHERE session_id = ? "
            "ORDER BY sequence_number",
            (session_id,),
        ).fetchall()
        return [AuditRecord.model_validate_json(row["data"]) for row in rows]

    def get_agent_records(
        self,
        agent_did: str,
        time_from: str = "",
        time_to: str = "",
    ) -> list[AuditRecord]:
        """Get all records for an agent, optionally filtered by time range."""
        query = "SELECT data FROM records WHERE agent_did = ?"
        params: list = [agent_did]

        if time_from:
            query += " AND timestamp >= ?"
            params.append(time_from)
        if time_to:
            query += " AND timestamp <= ?"
            params.append(time_to)

        query += " ORDER BY sequence_number"
        rows = self.conn.execute(query, params).fetchall()
        return [AuditRecord.model_validate_json(row["data"]) for row in rows]

    # ------------------------------------------------------------------
    # Session operations
    # ------------------------------------------------------------------

    def create_session(
        self,
        session_id: str,
        agent_did: str,
        principal_did: str,
        purpose: str,
        mode: str,
        authorization_vc_hash: Optional[str] = None,
        audit_language: str = "en",
    ) -> None:
        """Create a new session record."""
        self.conn.execute(
            """INSERT INTO sessions
               (session_id, agent_did, principal_did, purpose, mode,
                authorization_vc_hash, audit_language, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id, agent_did, principal_did, purpose, mode,
                authorization_vc_hash, audit_language,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()

    def close_session(self, session_id: str) -> None:
        """Mark a session as closed."""
        self.conn.execute(
            "UPDATE sessions SET status = 'closed', closed_at = ? "
            "WHERE session_id = ?",
            (datetime.now(timezone.utc).isoformat(), session_id),
        )
        self.conn.commit()

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get session metadata."""
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Chain state operations
    # ------------------------------------------------------------------

    def get_chain_state(self, agent_did: str) -> Optional[dict]:
        """Get current chain state for an agent."""
        row = self.conn.execute(
            "SELECT * FROM chain_state WHERE agent_did = ?", (agent_did,)
        ).fetchone()
        return dict(row) if row else None

    def update_chain_state(
        self,
        agent_did: str,
        last_hash: str,
        last_seq: int,
        total: int,
    ) -> None:
        """Update chain state after appending a record."""
        self.conn.execute(
            """INSERT INTO chain_state
               (agent_did, last_record_hash, last_sequence_number, total_records)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(agent_did) DO UPDATE SET
                   last_record_hash = excluded.last_record_hash,
                   last_sequence_number = excluded.last_sequence_number,
                   total_records = excluded.total_records""",
            (agent_did, last_hash, last_seq, total),
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Review operations (independent chain per Invariant 6 / 7.8)
    # ------------------------------------------------------------------

    def save_review(self, review: dict) -> None:
        """Save an audit review record."""
        self.conn.execute(
            """INSERT INTO reviews
               (review_id, session_id, auditor_did, timestamp,
                record_hash, previous_hash, data)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                review["review_id"],
                review["session_id"],
                review["auditor_did"],
                review["timestamp"],
                review["record_hash"],
                review.get("previous_hash"),
                json.dumps(review, ensure_ascii=False),
            ),
        )
        self.conn.commit()

    def get_session_reviews(self, session_id: str) -> list[dict]:
        """Get all reviews for a session."""
        rows = self.conn.execute(
            "SELECT data FROM reviews WHERE session_id = ? "
            "ORDER BY timestamp",
            (session_id,),
        ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def get_review_chain_state(self, auditor_did: str) -> Optional[dict]:
        """Get review chain state for an auditor."""
        row = self.conn.execute(
            "SELECT * FROM review_chain_state WHERE auditor_did = ?",
            (auditor_did,),
        ).fetchone()
        return dict(row) if row else None

    def update_review_chain_state(
        self,
        auditor_did: str,
        last_hash: str,
        last_seq: int,
    ) -> None:
        """Update review chain state."""
        self.conn.execute(
            """INSERT INTO review_chain_state
               (auditor_did, last_record_hash, last_sequence_number)
               VALUES (?, ?, ?)
               ON CONFLICT(auditor_did) DO UPDATE SET
                   last_record_hash = excluded.last_record_hash,
                   last_sequence_number = excluded.last_sequence_number""",
            (auditor_did, last_hash, last_seq),
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
