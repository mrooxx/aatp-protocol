"""
aatp_core/session.py — AATP Audit Session State Machine

A pure, synchronous state machine that manages one audit session's
lifecycle.  No I/O, no async, no storage — just state transitions
and record creation.

Lifecycle:
    __init__  →  ACTIVE  (INITIATION record auto-sealed)
                   │
              add_record()  (one or more business records)
                   │
                close()   →  CLOSED  (TERMINATION record auto-sealed)

Chain positioning:
    By default, AuditSession manages its own sequence numbers starting
    from sequence_start.  When used inside a Recorder that manages
    multiple concurrent sessions on the same agent chain, the Recorder
    calls set_chain_position() before each record to inject the correct
    global sequence number and previous hash.

Upper layers (aatp_recorder) handle persistence, non-blocking checks,
and AI tool interfaces.

Reference: AATP Conceptual Framework v0.44, Sections 4.2–4.5
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from .chain import compute_session_digest, seal_record
from .record import (
    AuditPointType,
    AuditRecord,
    Authorization,
    ChainMeta,
    Counterparty,
    OperatingMode,
    RecordHeader,
)
from .uuid7 import uuid7


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

class SessionState(str, Enum):
    """Lifecycle states of an audit session."""
    ACTIVE = "active"      # INITIATION sealed; accepting records
    CLOSED = "closed"      # TERMINATION sealed; no further records


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class AuditSession:
    """Pure state machine for one AATP audit session.

    On construction, an INITIATION record is automatically created and
    sealed.  The session is immediately in ACTIVE state and ready for
    business records.

    Args:
        mode:         Operating mode for this session.
        authorization: Authorization info (principal + agent DIDs, scope).
        private_key:  Ed25519 private key for signing all records in
                      this session.
        initiation_narrative: Human-readable narrative for the INITIATION
                              record.
        initiation_data: Structured data for the INITIATION record.
        counterparty: Counterparty info. Required for bilateral mode,
                      optional for unilateral, must be None for solo.
        previous_hash: Hash of the last record in the agent's global
                       chain (cross-session continuity). None if this
                       is the agent's very first session.
        sequence_start: Starting sequence number. 0 for the agent's
                        first-ever record; otherwise continues from the
                        global chain.
    """

    def __init__(
        self,
        *,
        mode: OperatingMode,
        authorization: Authorization,
        private_key: Ed25519PrivateKey,
        initiation_narrative: str,
        initiation_data: Dict[str, Any],
        counterparty: Optional[Counterparty] = None,
        previous_hash: Optional[str] = None,
        sequence_start: int = 0,
    ) -> None:
        self._session_id: str = uuid7()
        self._mode: OperatingMode = mode
        self._authorization: Authorization = authorization
        self._private_key: Ed25519PrivateKey = private_key
        self._counterparty: Optional[Counterparty] = counterparty
        self._state: SessionState = SessionState.ACTIVE

        # Chain state — tracks position for next record
        self._next_sequence: int = sequence_start
        self._previous_hash: Optional[str] = previous_hash

        # Sealed records (kept in memory for session_digest at close)
        self._records: List[AuditRecord] = []

        # Auto-seal INITIATION
        self._seal_lifecycle_record(
            audit_point_type=AuditPointType.INITIATION,
            narrative=initiation_narrative,
            structured_data=initiation_data,
        )

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def mode(self) -> OperatingMode:
        return self._mode

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def records(self) -> List[AuditRecord]:
        """All sealed records in this session (read-only copy)."""
        return list(self._records)

    @property
    def last_record(self) -> Optional[AuditRecord]:
        """Most recently sealed record, or None."""
        return self._records[-1] if self._records else None

    @property
    def next_sequence(self) -> int:
        """Sequence number that will be assigned to the next record."""
        return self._next_sequence

    @property
    def previous_hash(self) -> Optional[str]:
        """Hash of the most recently sealed record (for chain continuity)."""
        return self._previous_hash

    # ------------------------------------------------------------------
    # Chain position injection (for Recorder use)
    # ------------------------------------------------------------------

    def set_chain_position(
        self,
        sequence_number: int,
        previous_hash: Optional[str],
    ) -> None:
        """Set the chain position for the next record.

        Called by Recorder before each add_record() or close() when
        multiple sessions share the same agent chain.  When AuditSession
        is used standalone, the internal auto-increment is sufficient.
        """
        self._next_sequence = sequence_number
        self._previous_hash = previous_hash

    # ------------------------------------------------------------------
    # Record creation
    # ------------------------------------------------------------------

    def add_record(
        self,
        audit_point_type: AuditPointType,
        narrative: str,
        structured_data: Dict[str, Any],
        *,
        extension_type: Optional[str] = None,
        extension_justification: Optional[str] = None,
    ) -> AuditRecord:
        """Create and seal a business record.

        Args:
            audit_point_type: Must be one of the 8 core decision points,
                              PERIODIC_STATUS, or EXTENSION.
                              INITIATION and TERMINATION are not allowed
                              here — they are managed by the session.
            narrative:        Human-readable explanation.
            structured_data:  Machine-readable data dict.
            extension_type:   Required when audit_point_type is EXTENSION.
            extension_justification: Required for EXTENSION.

        Returns:
            The sealed AuditRecord.

        Raises:
            RuntimeError: If session is CLOSED.
            ValueError:   If audit_point_type is INITIATION or TERMINATION,
                          or if Pydantic validation fails.
        """
        self._require_active()

        # Guard: lifecycle types are session-managed
        if audit_point_type in (AuditPointType.INITIATION, AuditPointType.TERMINATION):
            raise ValueError(
                f"{audit_point_type.value} records are managed by the session. "
                f"Use close() for TERMINATION."
            )

        return self._create_and_seal(
            audit_point_type=audit_point_type,
            narrative=narrative,
            structured_data=structured_data,
            extension_type=extension_type,
            extension_justification=extension_justification,
        )

    def close(
        self,
        narrative: str,
        structured_data: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Close the session with a TERMINATION record.

        Computes session_digest over all prior records and includes it
        in the TERMINATION record's structured_data.

        Args:
            narrative:       Human-readable closing narrative.
            structured_data: Additional data to include. session_digest
                             and record_count are automatically added.

        Returns:
            The sealed TERMINATION AuditRecord.

        Raises:
            RuntimeError: If session is already CLOSED.
        """
        self._require_active()

        # Compute session digest over all records so far
        digest = compute_session_digest(self._records)

        # Build termination structured_data
        term_data: Dict[str, Any] = {
            "session_digest": digest,
            "record_count": len(self._records),
        }
        if structured_data:
            term_data.update(structured_data)

        record = self._seal_lifecycle_record(
            audit_point_type=AuditPointType.TERMINATION,
            narrative=narrative,
            structured_data=term_data,
        )

        self._state = SessionState.CLOSED
        return record

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_active(self) -> None:
        """Raise if session is not ACTIVE."""
        if self._state != SessionState.ACTIVE:
            raise RuntimeError(
                f"Session is {self._state.value}; cannot add records."
            )

    def _seal_lifecycle_record(
        self,
        audit_point_type: AuditPointType,
        narrative: str,
        structured_data: Dict[str, Any],
    ) -> AuditRecord:
        """Create and seal a lifecycle record (INITIATION or TERMINATION)."""
        return self._create_and_seal(
            audit_point_type=audit_point_type,
            narrative=narrative,
            structured_data=structured_data,
        )

    def _create_and_seal(
        self,
        audit_point_type: AuditPointType,
        narrative: str,
        structured_data: Dict[str, Any],
        extension_type: Optional[str] = None,
        extension_justification: Optional[str] = None,
    ) -> AuditRecord:
        """Assemble an AuditRecord, seal it, and advance chain state.

        This is the single path for all record creation — both lifecycle
        and business records flow through here.
        """
        seq = self._next_sequence

        # Build the unsigned record
        record = AuditRecord(
            header=RecordHeader(
                session_id=self._session_id,
                audit_point_type=audit_point_type,
                mode=self._mode,
                extension_type=extension_type,
                extension_justification=extension_justification,
            ),
            narrative=narrative,
            structured_data=structured_data,
            authorization=self._authorization,
            counterparty=self._counterparty,
            chain=ChainMeta(
                sequence_number=seq,
                previous_hash=self._previous_hash if seq > 0 else None,
            ),
        )

        # Seal: canonicalize → hash → sign → produce immutable record
        sealed = seal_record(
            record=record,
            private_key=self._private_key,
            previous_hash=self._previous_hash if seq > 0 else None,
        )

        # Advance chain state
        self._records.append(sealed)
        self._previous_hash = sealed.chain.record_hash
        self._next_sequence = seq + 1

        return sealed
