"""
aatp_recorder — The Accountant Module.

Exposes 3 tool functions for AI agents to call at decision points:
- start_session():    Begin a new audit session
- record_decision():  Record a decision within a session
- end_session():      Close a session with outcome summary

Architecture:
    AI Agent (probabilistic) → Recorder (deterministic bridge) → Core

The recorder wraps AuditSession (state machine + sealing) and Storage
(persistence), adding non-blocking quality checks.  All crypto, hashing,
and chain management are handled by aatp_core; the AI only provides
content.

Chain management:
    The Recorder maintains a single global chain position (sequence
    number + previous hash) for the agent.  Multiple concurrent sessions
    share this chain — like a shared voucher numbering system in
    accounting.  The Recorder injects the correct position into each
    AuditSession before every record creation via set_chain_position().

Reference: AATP Conceptual Framework v0.44, Sections 4.2–4.5, 7.2, 7.9
"""

import re
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from aatp_core.record import (
    AuditPointType,
    Authorization,
    Counterparty,
    OperatingMode,
)
from aatp_core.session import AuditSession, SessionState
from aatp_core.storage import Storage


class Recorder:
    """AATP Recorder — creates, seals, and persists audit records.

    Manages multiple concurrent sessions for one agent.  Each session
    is an AuditSession state machine; the recorder adds persistence,
    global chain sequencing, and non-blocking quality checks on top.

    Args:
        agent_did:     W3C DID of the AI agent.
        principal_did: W3C DID of the human principal.
        scope_summary: Human-readable authorization scope.
        private_key:   Ed25519 private key for signing.
        storage:       Storage backend (SQLite).
        authorization_vc_hash: Optional VC hash for Level 2 review.
        audit_language: BCP 47 language tag (default "en").
    """

    def __init__(
        self,
        agent_did: str,
        principal_did: str,
        scope_summary: str,
        private_key: Ed25519PrivateKey,
        storage: Storage,
        authorization_vc_hash: Optional[str] = None,
        audit_language: str = "en",
    ) -> None:
        self.agent_did = agent_did
        self.principal_did = principal_did
        self.scope_summary = scope_summary
        self.private_key = private_key
        self.storage = storage
        self.authorization_vc_hash = authorization_vc_hash
        self.audit_language = audit_language

        # Active sessions keyed by session_id
        self._sessions: Dict[str, AuditSession] = {}

        # Global chain state — single sequence across all sessions.
        # Like a shared voucher numbering system: session A gets #1,
        # session B gets #2, session A gets #3, etc.
        state = self.storage.get_chain_state(self.agent_did)
        if state:
            self._next_sequence: int = state["last_sequence_number"] + 1
            self._previous_hash: Optional[str] = state["last_record_hash"]
        else:
            self._next_sequence = 0
            self._previous_hash = None

    # ------------------------------------------------------------------
    # Authorization helper
    # ------------------------------------------------------------------

    def _make_authorization(self) -> Authorization:
        """Build Authorization from recorder config."""
        return Authorization(
            principal_did=self.principal_did,
            agent_did=self.agent_did,
            scope_summary=self.scope_summary,
            authorization_vc_hash=self.authorization_vc_hash,
        )

    # ------------------------------------------------------------------
    # Chain state management
    # ------------------------------------------------------------------

    def _advance_chain(self, session: AuditSession) -> None:
        """Update global chain state and persist after a record is sealed."""
        record = session.last_record
        if record is None:
            return

        # Advance in-memory global state
        self._next_sequence = record.chain.sequence_number + 1
        self._previous_hash = record.chain.record_hash

        # Persist record
        self.storage.save_record(record)

        # Persist chain state
        state = self.storage.get_chain_state(self.agent_did)
        total = (state["total_records"] + 1) if state else 1
        self.storage.update_chain_state(
            agent_did=self.agent_did,
            last_hash=record.chain.record_hash,
            last_seq=record.chain.sequence_number,
            total=total,
        )

    def _inject_chain_position(self, session: AuditSession) -> None:
        """Inject current global chain position into a session."""
        session.set_chain_position(self._next_sequence, self._previous_hash)

    # ------------------------------------------------------------------
    # Non-blocking checks (semantic contracts 7.2, 7.9)
    # ------------------------------------------------------------------

    @staticmethod
    def _run_purpose_drift_check(
        session_purpose: str, narrative: str
    ) -> List[str]:
        """Non-blocking purpose drift detection (semantic contract 7.2).

        Simple v0.1 implementation: word-stem overlap check.
        Uses first 5 chars of each word (>=4 chars) as rough stemming.
        Returns list of flags (empty if no drift detected).

        This is intentionally naive — a production system would use
        embeddings or an LLM judge.  But even this catches obvious
        cases like a subscription-review session suddenly recording
        a laptop purchase.
        """
        flags: List[str] = []

        def stems(text: str) -> set:
            return set(
                w.lower()[:5] for w in re.findall(r"\b\w{4,}\b", text)
            )

        purpose_stems = stems(session_purpose)
        narrative_stems = stems(narrative)

        if purpose_stems and narrative_stems:
            overlap = len(purpose_stems & narrative_stems)
            max_possible = min(len(purpose_stems), len(narrative_stems))
            if max_possible > 0 and overlap / max_possible < 0.15:
                flags.append("PURPOSE_DRIFT")

        return flags

    @staticmethod
    def _run_numeric_consistency_check(
        narrative: str, structured_data: Dict[str, Any]
    ) -> List[str]:
        """Non-blocking numeric consistency check (semantic contract 7.9).

        Extracts currency-like amounts from narrative and checks
        whether they appear in structured_data values.  Flags
        mismatches — e.g. narrative says "$15.99" but structured_data
        has no 15.99.
        """
        flags: List[str] = []

        # Extract numbers that look like currency amounts
        narrative_numbers = set(
            float(m)
            for m in re.findall(
                r"\$?([\d]+\.[\d]{2})(?:\b|[^.\d]|$)", narrative
            )
        )

        if not narrative_numbers:
            return flags

        # Collect numeric values from structured_data (flat scan)
        data_numbers: set = set()
        for v in structured_data.values():
            if isinstance(v, (int, float)):
                data_numbers.add(float(v))

        # Check if narrative amounts appear in structured_data
        for n in narrative_numbers:
            if n not in data_numbers:
                flags.append("NUMERIC_MISMATCH")
                break  # One flag is enough

        return flags

    # ------------------------------------------------------------------
    # Tool function 1: start_session
    # ------------------------------------------------------------------

    def start_session(
        self,
        purpose: str,
        mode: str = "solo",
        counterparty_did: Optional[str] = None,
        counterparty_ref: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start a new audit session.

        Creates an AuditSession (which auto-seals INITIATION), persists
        the INITIATION record and session metadata to storage.

        Args:
            purpose:          Human-readable session purpose.
            mode:             "solo", "unilateral", or "bilateral".
            counterparty_did: Counterparty DID (required for bilateral).
            counterparty_ref: Counterparty reference (fallback identifier).

        Returns:
            Dict with session_id, record_id, sequence_number, record_hash.
        """
        op_mode = OperatingMode(mode)

        # Build counterparty if needed
        counterparty = None
        if counterparty_did or counterparty_ref:
            counterparty = Counterparty(
                counterparty_did=counterparty_did,
                counterparty_ref=counterparty_ref,
            )

        # Create session — INITIATION is auto-sealed using current
        # global chain position
        session = AuditSession(
            mode=op_mode,
            authorization=self._make_authorization(),
            private_key=self.private_key,
            initiation_narrative=f"Session initiated: {purpose}",
            initiation_data={
                "purpose": purpose,
                "mode": mode,
                "audit_language": self.audit_language,
            },
            counterparty=counterparty,
            previous_hash=self._previous_hash,
            sequence_start=self._next_sequence,
        )

        # Persist session metadata
        self.storage.create_session(
            session_id=session.session_id,
            agent_did=self.agent_did,
            principal_did=self.principal_did,
            purpose=purpose,
            mode=mode,
            authorization_vc_hash=self.authorization_vc_hash,
            audit_language=self.audit_language,
        )

        # Persist INITIATION record and advance global chain
        self._advance_chain(session)

        # Track active session
        self._sessions[session.session_id] = session

        initiation = session.last_record
        return {
            "session_id": session.session_id,
            "record_id": initiation.header.record_id,
            "sequence_number": initiation.chain.sequence_number,
            "record_hash": initiation.chain.record_hash,
            "status": "active",
        }

    # ------------------------------------------------------------------
    # Tool function 2: record_decision
    # ------------------------------------------------------------------

    def record_decision(
        self,
        session_id: str,
        audit_point_type: str,
        narrative: str,
        structured_data: Dict[str, Any],
        *,
        extension_type: Optional[str] = None,
        extension_justification: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a decision within an active session.

        Runs non-blocking quality checks, then creates and persists
        the record.

        Args:
            session_id:       Target session.
            audit_point_type: One of the 8 core types, PERIODIC_STATUS,
                              or EXTENSION.
            narrative:        Human-readable decision explanation.
            structured_data:  Machine-readable decision data.
            extension_type:   Required for EXTENSION records.
            extension_justification: Required for EXTENSION records.

        Returns:
            Dict with record_id, sequence_number, record_hash,
            recorder_flags.

        Raises:
            ValueError: If session not found, not active, or invalid type.
        """
        session = self._get_active_session(session_id)

        # Run non-blocking checks
        session_meta = self.storage.get_session(session_id)
        purpose = session_meta["purpose"] if session_meta else ""

        flags: List[str] = []
        flags.extend(self._run_purpose_drift_check(purpose, narrative))
        flags.extend(
            self._run_numeric_consistency_check(narrative, structured_data)
        )

        # Include flags in structured_data so they're part of the
        # sealed record (auditable)
        if flags:
            structured_data = dict(structured_data)  # don't mutate caller's
            structured_data["recorder_flags"] = flags

        # Inject global chain position before creating record
        self._inject_chain_position(session)

        # Create and seal record
        apt = AuditPointType(audit_point_type)
        record = session.add_record(
            audit_point_type=apt,
            narrative=narrative,
            structured_data=structured_data,
            extension_type=extension_type,
            extension_justification=extension_justification,
        )

        # Persist and advance global chain
        self._advance_chain(session)

        return {
            "record_id": record.header.record_id,
            "sequence_number": record.chain.sequence_number,
            "record_hash": record.chain.record_hash,
            "recorder_flags": flags,
        }

    # ------------------------------------------------------------------
    # Tool function 3: end_session
    # ------------------------------------------------------------------

    def end_session(
        self,
        session_id: str,
        outcome_summary: str,
        total_value: Optional[float] = None,
        outstanding_obligations: Optional[str] = None,
    ) -> Dict[str, Any]:
        """End a session with outcome summary.

        Creates a TERMINATION record (with session_digest computed
        automatically by AuditSession.close()), persists it, and
        marks the session as closed.

        Args:
            session_id:              Target session.
            outcome_summary:         Human-readable outcome.
            total_value:             Optional total monetary value.
            outstanding_obligations: Optional note on remaining obligations.

        Returns:
            Dict with record_id, session_digest, sequence_number,
            record_hash, total_records.

        Raises:
            ValueError: If session not found or not active.
        """
        session = self._get_active_session(session_id)

        # Build termination structured_data
        term_data: Dict[str, Any] = {
            "outcome_summary": outcome_summary,
        }
        if total_value is not None:
            term_data["total_value"] = total_value
        if outstanding_obligations:
            term_data["outstanding_obligations"] = outstanding_obligations

        # Inject global chain position before closing
        self._inject_chain_position(session)

        # Close session (auto-computes session_digest, seals TERMINATION)
        record = session.close(
            narrative=f"Session completed: {outcome_summary}",
            structured_data=term_data,
        )

        # Persist TERMINATION record and advance global chain
        self._advance_chain(session)

        # Close session in storage
        self.storage.close_session(session_id)

        # Remove from active sessions
        del self._sessions[session_id]

        return {
            "record_id": record.header.record_id,
            "session_id": session_id,
            "session_digest": record.structured_data.get("session_digest"),
            "sequence_number": record.chain.sequence_number,
            "record_hash": record.chain.record_hash,
            "total_records": record.structured_data.get("record_count"),
            "status": "closed",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_active_session(self, session_id: str) -> AuditSession:
        """Retrieve an active in-memory session or raise."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(
                f"Session not found (not active in this recorder): "
                f"{session_id}"
            )
        if session.state != SessionState.ACTIVE:
            raise ValueError(
                f"Session is {session.state.value}: {session_id}"
            )
        return session
