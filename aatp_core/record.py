"""
aatp_core/record.py — AATP Audit Record Data Model

This module defines the canonical data structures for AATP audit records.
It is the single source of truth: JSON Schema is auto-exported from these
Pydantic models, never hand-written separately.

Design decisions documented here become normative via the Technical Spec.

Reference: AATP Conceptual Framework v0.44, Sections 4.2–4.5, 11.4
"""

# NOTE: `from __future__ import annotations` is intentionally omitted.
# It causes RecursionError with Pydantic v2 on Python 3.10 when
# combined with recursive type aliases. Python 3.10+ supports
# `dict[str, ...]` / `list[...]` natively at runtime, so it is
# not needed here.

import json
import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator

from .uuid7 import uuid7


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Semantic contract 7.11: 32KB max per record after serialization.
# This is the ONE case where the recorder rejects outright.
MAX_RECORD_SIZE_BYTES = 32 * 1024


# ---------------------------------------------------------------------------
# JSON-safe type (for structured_data)
# ---------------------------------------------------------------------------

# JsonValue is typed as Any to avoid recursive type alias issues on
# Python < 3.12 + Pydantic v2.  Runtime validation of JSON-safety
# (no NaN/Inf, no datetime/bytes) is enforced by _check_no_nan_inf().
JsonPrimitive = Union[str, int, float, bool, None]
JsonValue = Any


def _check_no_nan_inf(value: Any, path: str = "structured_data") -> None:
    """Recursively reject NaN and Infinity in JSON values.

    IEEE 754 special values are not valid JSON (RFC 8259 §6) and would
    break canonical serialization determinism across implementations.
    """
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError(
                f"NaN and Infinity are not valid JSON numbers "
                f"(found in {path})"
            )
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_no_nan_inf(v, path=f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _check_no_nan_inf(v, path=f"{path}[{i}]")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AuditPointType(str, Enum):
    """Record types in an AATP audit chain.

    AATP defines three categories of record types that share the same
    record envelope (narrative + structured data, sealed and chained):

    1. **Session lifecycle records** — INITIATION and TERMINATION mark
       the boundaries of an audit session. They are not decision points.

    2. **The eight core decision points (Invariant 4)** — OPENING through
       CLOSING. These are the normative minimum set of auditable decision
       moments in a transaction lifecycle. Invariant 4 refers exclusively
       to these eight; they form a closed core set.

    3. **Supplementary record types** — PERIODIC_STATUS provides
       continuous accountability between decision points (CF v0.44
       §4.2.2). EXTENSION accommodates domain-specific moments not
       covered by the core eight, under the constraints of CF v0.44
       §4.2.1.

    All record types use the same AuditRecord structure and are subject
    to the same hash-chaining and three-level review.
    """
    # --- Session lifecycle (not decision points) ---
    INITIATION = "initiation"
    TERMINATION = "termination"

    # --- Eight core decision points (Invariant 4) ---
    OPENING = "opening"
    OFFER = "offer"
    COUNTER_OFFER = "counter_offer"
    AGREEMENT_OR_REJECTION = "agreement_or_rejection"
    PAYMENT_SENT = "payment_sent"
    PAYMENT_CONFIRMED = "payment_confirmed"
    PROBLEM_OR_DISPUTE = "problem_or_dispute"
    CLOSING = "closing"

    # --- Supplementary record types ---
    PERIODIC_STATUS = "periodic_status"
    EXTENSION = "extension"


class OperatingMode(str, Enum):
    """Three operating modes with increasing assurance (CF v0.44 §4.5)."""
    SOLO = "solo"
    UNILATERAL = "unilateral"
    BILATERAL = "bilateral"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class RecordHeader(BaseModel):
    """Metadata that identifies and classifies this audit record."""

    protocol_version: str = Field(
        default="0.1.0",
        description="AATP protocol version (semver). Distinct from SDK version.",
        pattern=r"^\d+\.\d+\.\d+$",
    )
    record_id: str = Field(
        default_factory=uuid7,
        description="Unique identifier for this record. UUID v7 (time-ordered).",
    )
    session_id: str = Field(
        ...,
        description="Session identifier (UUID v7), assigned at session start. "
                    "All records in a session share the same session_id.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of record creation. Monotonicity enforced "
                    "by chain.py / verifier.py, not at model level.",
    )
    audit_point_type: AuditPointType = Field(
        ...,
        description="The type of decision point, lifecycle event, or "
                    "supplementary record.",
    )
    mode: OperatingMode = Field(
        ...,
        description="Operating mode for this session.",
    )
    audit_language: str = Field(
        default="en",
        description="BCP 47 language tag for the narrative.",
    )
    extension_type: Optional[str] = Field(
        default=None,
        description="Domain-specific type when audit_point_type is EXTENSION.",
    )
    extension_justification: Optional[str] = Field(
        default=None,
        description="Why core types are insufficient. Required for EXTENSION.",
    )

    @model_validator(mode="after")
    def validate_extension_fields(self) -> "RecordHeader":
        if self.audit_point_type == AuditPointType.EXTENSION:
            if not self.extension_type:
                raise ValueError(
                    "extension_type is required when audit_point_type is EXTENSION"
                )
            if not self.extension_justification:
                raise ValueError(
                    "extension_justification is required for EXTENSION "
                    "(CF v0.44 §4.2.1)"
                )
        else:
            if self.extension_type is not None:
                raise ValueError(
                    "extension_type must be None for non-extension record types"
                )
            if self.extension_justification is not None:
                raise ValueError(
                    "extension_justification must be None for non-extension "
                    "record types"
                )
        return self


class Authorization(BaseModel):
    """Links this record to the human principal's delegated authority.

    Invariant 7: Every audit trail must trace back to a human principal.
    """

    principal_did: str = Field(
        ...,
        description="W3C DID of the human principal who delegated authority.",
        pattern=r"^did:",
    )
    agent_did: str = Field(
        ...,
        description="W3C DID of the agent acting under delegation. "
                    "This is the entity that signs records.",
        pattern=r"^did:",
    )
    scope_summary: str = Field(
        ...,
        description="Human-readable summary of what the agent is authorized "
                    "to do.",
    )
    authorization_vc_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of the authorization Verifiable Credential. "
                    "Optional in v0.x; enables VC integrity verification in "
                    "Level 2 review.",
    )
    credential_reference: Optional[str] = Field(
        default=None,
        description="Reference to the VC document. Optional in v0.x.",
    )


class Counterparty(BaseModel):
    """Information about the other party in the transaction.

    In Bilateral mode, counterparty_did is required for cross-referencing.
    In Unilateral mode, at least one identifier (did or ref) must exist.
    """

    counterparty_did: Optional[str] = Field(
        default=None,
        description="W3C DID of the counterparty. Required in bilateral mode.",
        pattern=r"^did:",
    )
    counterparty_ref: Optional[str] = Field(
        default=None,
        description="Non-DID identifier (domain, email, account ID). "
                    "Audit anchor when DID is unavailable.",
    )
    counterparty_last_seq: Optional[int] = Field(
        default=None,
        description="Last sequence number seen from counterparty. "
                    "Enables cross-reference gap detection in bilateral mode.",
        ge=0,
    )

    @model_validator(mode="after")
    def validate_at_least_one_identifier(self) -> "Counterparty":
        if self.counterparty_did is None and self.counterparty_ref is None:
            raise ValueError(
                "Counterparty must have at least one identifier: "
                "counterparty_did or counterparty_ref"
            )
        return self


class Signature(BaseModel):
    """Cryptographic signature over the record hash.

    Structured as an object (not a bare hex string) to be self-describing:
    the algorithm and signer identity travel with the signature value.
    Design adopted from v0.1 implementation.
    """

    algorithm: str = Field(
        default="Ed25519",
        description="Signature algorithm identifier.",
    )
    signer: str = Field(
        ...,
        description="DID of the signing entity (must match authorization.agent_did).",
        pattern=r"^did:",
    )
    value: str = Field(
        ...,
        description="Hex-encoded signature bytes.",
        pattern=r"^[0-9a-f]+$",
    )


class ChainMeta(BaseModel):
    """Hash chain linkage and cryptographic seal.

    Invariant 3: Every record is sealed at creation and linked to the
    previous record, forming a tamper-evident chain.

    Fields are populated by chain.py at record creation time, NOT by
    the caller.
    """

    sequence_number: int = Field(
        ...,
        description="Monotonically increasing position in the chain. "
                    "Genesis record is sequence 0.",
        ge=0,
    )
    previous_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of the previous record's canonical bytes. "
                    "None only for the genesis record (sequence 0).",
    )
    record_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of this record's canonical bytes "
                    "(computed over all fields except record_hash and "
                    "signature). Populated by chain.py.",
    )
    signature: Optional[Signature] = Field(
        default=None,
        description="Ed25519 signature over record_hash. "
                    "Populated by chain.py.",
    )

    @model_validator(mode="after")
    def validate_genesis(self) -> "ChainMeta":
        if self.sequence_number == 0 and self.previous_hash is not None:
            raise ValueError(
                "Genesis record (sequence_number=0) must not have a previous_hash"
            )
        if self.sequence_number > 0 and self.previous_hash is None:
            raise ValueError(
                "Non-genesis record must have a previous_hash"
            )
        return self


# ---------------------------------------------------------------------------
# Top-level Record
# ---------------------------------------------------------------------------

class AuditRecord(BaseModel):
    """A single AATP audit record.

    This is the atomic unit of the AATP audit trail. Every record contains:
    - header:          Identification and classification metadata
    - narrative:       Human-readable explanation (Invariant 2, left side)
    - structured_data: Machine-readable data (Invariant 2, right side)
    - authorization:   Link to human principal + agent identity (Invariant 7)
    - counterparty:    Other party info (optional, mode-dependent)
    - chain:           Hash chain linkage and cryptographic seal (Invariant 3)
    """

    header: RecordHeader
    narrative: str = Field(
        ...,
        min_length=1,
        description="Human-readable explanation of the decision or event.",
    )
    structured_data: Dict[str, Any] = Field(
        ...,
        description="Machine-readable data for automated verification. "
                    "JSON-safe only (no NaN/Inf/datetime/bytes).",
    )
    authorization: Authorization
    counterparty: Optional[Counterparty] = Field(default=None)
    chain: ChainMeta

    @field_validator("structured_data")
    @classmethod
    def validate_structured_data_json_safe(
        cls, v: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not v:
            raise ValueError("structured_data must contain at least one field")
        _check_no_nan_inf(v)
        return v

    @model_validator(mode="after")
    def validate_mode_counterparty(self) -> "AuditRecord":
        """Enforce mode-counterparty consistency.

        Solo:       counterparty must be None.
        Bilateral:  counterparty required with counterparty_did.
        Unilateral: counterparty optional.
        """
        mode = self.header.mode
        if mode == OperatingMode.SOLO:
            if self.counterparty is not None:
                raise ValueError(
                    "Solo mode records must not have counterparty information"
                )
        elif mode == OperatingMode.BILATERAL:
            if self.counterparty is None:
                raise ValueError(
                    "Bilateral mode records must include counterparty information"
                )
            if self.counterparty.counterparty_did is None:
                raise ValueError(
                    "Bilateral mode requires counterparty_did for "
                    "cross-reference verification"
                )
        return self

    def hashable_dict(self) -> dict:
        """Return the record as a dict excluding derived chain fields.

        Excludes chain.record_hash and chain.signature — these are
        computed over the remaining fields.

        Pipeline: hashable_dict() → canonicalize() → SHA-256 → sign
        """
        d = self.model_dump(mode="json")
        d["chain"].pop("record_hash", None)
        d["chain"].pop("signature", None)
        return d

    def to_json(self, indent: int = 2) -> str:
        """Serialize to pretty-printed JSON (for storage/display, not hashing)."""
        return self.model_dump_json(indent=indent)


# ---------------------------------------------------------------------------
# Size validation (semantic contract 7.11)
# ---------------------------------------------------------------------------

def validate_record_size(record: AuditRecord) -> None:
    """Enforce 32KB max per record after serialization.

    This is the ONE case where the recorder rejects outright.
    Raises ValueError if record exceeds limit.
    """
    serialized = record.model_dump_json().encode("utf-8")
    if len(serialized) > MAX_RECORD_SIZE_BYTES:
        raise ValueError(
            f"Record exceeds 32KB limit: {len(serialized)} bytes. "
            f"This indicates a bug or abuse (semantic contract 7.11)."
        )


# ---------------------------------------------------------------------------
# JSON Schema export
# ---------------------------------------------------------------------------

def export_json_schema() -> str:
    """Export the AuditRecord JSON Schema.

    Authoritative schema for non-Python implementations.
    Generated from Pydantic — never hand-edited.
    """
    schema = AuditRecord.model_json_schema()
    return json.dumps(schema, indent=2)


if __name__ == "__main__":
    print(export_json_schema())
