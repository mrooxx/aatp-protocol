"""
aatp_reviewer — The Auditor Module.

Exposes 4 tool functions for audit AI to call:
- verify_chain():          Level 1 — integrity check
- check_conformance():     Level 2 — authorization and consistency check
- get_session_for_review(): Level 3 prep — formatted records for AI review
- submit_review():         Level 3 — store audit findings

Plus bilateral-mode additions:
- verify_transitions():    Level 1 ext — decision-point sequence validation
- verify_bilateral():      Cross-chain verification for bilateral sessions

Level 1 and 2 are automated (deterministic).
Level 3 is performed by the audit AI (probabilistic).

Architecture:
    Audit AI → Reviewer → Core (verify) + Storage (read/write)

The reviewer operates on an INDEPENDENT chain from the agent
(Invariant 6: agent ≠ auditor).  Review records are signed with
the auditor's own key and stored in a separate chain.

Reference: AATP Conceptual Framework v0.44, Sections 5.1–5.3, 7.6–7.8
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aatp_core.canonical import canonicalize
from aatp_core.chain import verify_chain as core_verify_chain
from aatp_core.crypto import sha256_hex, sign_bytes
from aatp_core.record import AuditPointType, AuditRecord
from aatp_core.storage import Storage
from aatp_core.uuid7 import uuid7


# ---------------------------------------------------------------------------
# Decision-point transition table (locked v0.1.0)
# ---------------------------------------------------------------------------
# Reference: Multi-AI review (GPT/Gemini/Grok consensus) + CF v0.44 §4.2
#
# This table defines PROTOCOL-LEGAL transitions within a single chain.
# It answers: "Is this sequence of audit_point_types structurally valid?"
#
# This is Level 1 (structural integrity), NOT Level 3 (reasonableness).
# Whether a transition is *wise* is the audit AI's job.

# Transparent types: can appear between any two decision records.
# They are skipped during transition validation.
TRANSPARENT_TYPES: Set[AuditPointType] = {
    AuditPointType.PERIODIC_STATUS,
    AuditPointType.EXTENSION,
}

# Shorthand aliases for readability
_INIT = AuditPointType.INITIATION
_TERM = AuditPointType.TERMINATION
_OPEN = AuditPointType.OPENING
_OFFR = AuditPointType.OFFER
_COFF = AuditPointType.COUNTER_OFFER
_AGRJ = AuditPointType.AGREEMENT_OR_REJECTION
_PAYS = AuditPointType.PAYMENT_SENT
_PAYC = AuditPointType.PAYMENT_CONFIRMED
_PROB = AuditPointType.PROBLEM_OR_DISPUTE
_CLOS = AuditPointType.CLOSING

VALID_TRANSITIONS: Dict[AuditPointType, Set[AuditPointType]] = {
    # Lifecycle entry
    _INIT: {_OPEN},

    # Post-opening: negotiation, direct settlement (Solo), or empty session
    _OPEN: {_OFFR, _COFF, _AGRJ, _PAYS, _PAYC, _CLOS},

    # Negotiation phase
    _OFFR: {_COFF, _AGRJ, _PROB, _CLOS,
            _PAYS, _PAYC},              # bilateral: counterparty accepted, go to settlement
    _COFF: {_COFF, _OFFR, _AGRJ, _PROB, _CLOS,
            _PAYS, _PAYC},              # bilateral: counterparty accepted, go to settlement

    # Settlement phase
    _AGRJ: {_PAYS, _PAYC, _CLOS, _COFF, _OFFR, _PROB},
    _PAYS: {_PAYC, _PROB, _CLOS},
    _PAYC: {_CLOS, _PROB},

    # Dispute handling
    _PROB: {_AGRJ, _PAYS, _PAYC, _CLOS, _PROB},

    # Lifecycle exit
    _CLOS: {_TERM},
}


# ---------------------------------------------------------------------------
# Transition verification (single-chain)
# ---------------------------------------------------------------------------

def verify_transitions(records: List[AuditRecord]) -> Dict[str, Any]:
    """Verify decision-point sequence validity for a single chain.

    Filters out TRANSPARENT_TYPES, then checks:
    1. First non-transparent record is INITIATION
    2. Last non-transparent record is TERMINATION
    3. No records after TERMINATION
    4. Each pairwise transition is in VALID_TRANSITIONS

    Args:
        records: All records in a single chain, in sequence order.

    Returns:
        Dict with transitions_valid flag and list of violations.
    """
    result: Dict[str, Any] = {
        "transitions_valid": True,
        "violations": [],
        "total_decision_records": 0,
    }

    if not records:
        return result

    # Sort by sequence number (defensive)
    sorted_records = sorted(records, key=lambda r: r.chain.sequence_number)

    # Check: no records after TERMINATION (including transparent types)
    term_seen = False
    for r in sorted_records:
        if term_seen:
            result["transitions_valid"] = False
            result["violations"].append({
                "type": "POST_TERMINATION_RECORD",
                "sequence_number": r.chain.sequence_number,
                "audit_point_type": r.header.audit_point_type.value,
                "message": "Record found after TERMINATION",
            })
        if r.header.audit_point_type == _TERM:
            term_seen = True

    # Filter to decision records (skip transparent types)
    decision_records = [
        r for r in sorted_records
        if r.header.audit_point_type not in TRANSPARENT_TYPES
    ]
    result["total_decision_records"] = len(decision_records)

    if not decision_records:
        return result

    # Check: first decision record must be INITIATION
    first_type = decision_records[0].header.audit_point_type
    if first_type != _INIT:
        result["transitions_valid"] = False
        result["violations"].append({
            "type": "MISSING_INITIATION",
            "sequence_number": decision_records[0].chain.sequence_number,
            "audit_point_type": first_type.value,
            "message": (
                f"First decision record must be INITIATION, "
                f"found {first_type.value}"
            ),
        })

    # Check: last decision record must be TERMINATION
    last_type = decision_records[-1].header.audit_point_type
    if last_type != _TERM:
        result["transitions_valid"] = False
        result["violations"].append({
            "type": "MISSING_TERMINATION",
            "sequence_number": decision_records[-1].chain.sequence_number,
            "audit_point_type": last_type.value,
            "message": (
                f"Last decision record must be TERMINATION, "
                f"found {last_type.value}"
            ),
        })

    # Check: pairwise transitions
    for i in range(len(decision_records) - 1):
        current = decision_records[i]
        next_rec = decision_records[i + 1]
        current_type = current.header.audit_point_type
        next_type = next_rec.header.audit_point_type

        allowed = VALID_TRANSITIONS.get(current_type)
        if allowed is None:
            result["transitions_valid"] = False
            result["violations"].append({
                "type": "UNKNOWN_TYPE",
                "sequence_number": current.chain.sequence_number,
                "audit_point_type": current_type.value,
                "message": f"Unknown audit point type: {current_type.value}",
            })
        elif next_type not in allowed:
            result["transitions_valid"] = False
            result["violations"].append({
                "type": "INVALID_TRANSITION",
                "from_sequence": current.chain.sequence_number,
                "from_type": current_type.value,
                "to_sequence": next_rec.chain.sequence_number,
                "to_type": next_type.value,
                "message": (
                    f"Invalid transition: {current_type.value} → "
                    f"{next_type.value}"
                ),
            })

    return result


# ---------------------------------------------------------------------------
# Bilateral cross-chain verification
# ---------------------------------------------------------------------------

def verify_bilateral(
    chain_a: List[AuditRecord],
    chain_b: List[AuditRecord],
    public_key_a: Ed25519PublicKey,
    public_key_b: Ed25519PublicKey,
) -> Dict[str, Any]:
    """Cross-chain verification for bilateral sessions.

    Performs:
    1. L1 integrity on each chain independently (hash, sig, links)
    2. Transition sequence validation on each chain
    3. counterparty_last_seq continuity (no gaps in cross-references)
    4. Amount consistency between chains
    5. Boundary constraints (first/last records)

    Args:
        chain_a: All records from Agent A, in sequence order.
        chain_b: All records from Agent B, in sequence order.
        public_key_a: Agent A's public key for signature verification.
        public_key_b: Agent B's public key for signature verification.

    Returns:
        Comprehensive bilateral verification result.
    """
    result: Dict[str, Any] = {
        "bilateral_valid": True,
        "agent_a": {
            "total_records": len(chain_a),
            "l1_integrity": None,
            "transitions": None,
        },
        "agent_b": {
            "total_records": len(chain_b),
            "l1_integrity": None,
            "transitions": None,
        },
        "cross_reference": {
            "valid": True,
            "references_checked": 0,
            "violations": [],
        },
        "amount_consistency": {
            "valid": True,
            "violations": [],
        },
    }

    # --- 1. L1 integrity on each chain ---
    l1_a = core_verify_chain(chain_a, public_key_a)
    l1_b = core_verify_chain(chain_b, public_key_b)

    result["agent_a"]["l1_integrity"] = l1_a
    result["agent_b"]["l1_integrity"] = l1_b

    if not l1_a["chain_valid"]:
        result["bilateral_valid"] = False
    if not l1_b["chain_valid"]:
        result["bilateral_valid"] = False

    # --- 2. Transition sequence validation ---
    trans_a = verify_transitions(chain_a)
    trans_b = verify_transitions(chain_b)

    result["agent_a"]["transitions"] = trans_a
    result["agent_b"]["transitions"] = trans_b

    if not trans_a["transitions_valid"]:
        result["bilateral_valid"] = False
    if not trans_b["transitions_valid"]:
        result["bilateral_valid"] = False

    # --- 3. Cross-reference continuity ---
    # Build sequence→record index for each chain
    sorted_a = sorted(chain_a, key=lambda r: r.chain.sequence_number)
    sorted_b = sorted(chain_b, key=lambda r: r.chain.sequence_number)

    seq_set_a = {r.chain.sequence_number for r in sorted_a}
    seq_set_b = {r.chain.sequence_number for r in sorted_b}

    # Check A's references to B
    _check_cross_refs(
        source_chain=sorted_a,
        target_seq_set=seq_set_b,
        source_label="A",
        target_label="B",
        xref_result=result["cross_reference"],
    )

    # Check B's references to A
    _check_cross_refs(
        source_chain=sorted_b,
        target_seq_set=seq_set_a,
        source_label="B",
        target_label="A",
        xref_result=result["cross_reference"],
    )

    if not result["cross_reference"]["valid"]:
        result["bilateral_valid"] = False

    # --- 4. Amount consistency ---
    _check_amount_consistency(sorted_a, sorted_b, result["amount_consistency"])

    if not result["amount_consistency"]["valid"]:
        result["bilateral_valid"] = False

    return result


def _check_cross_refs(
    source_chain: List[AuditRecord],
    target_seq_set: Set[int],
    source_label: str,
    target_label: str,
    xref_result: Dict[str, Any],
) -> None:
    """Check counterparty_last_seq references from source to target chain.

    For each record in source_chain that has a counterparty_last_seq,
    verify the referenced sequence exists in target_seq_set.
    Also check that cross-references are monotonically non-decreasing.
    """
    last_xref: Optional[int] = None

    for record in source_chain:
        cp = record.counterparty
        if cp is None or cp.counterparty_last_seq is None:
            continue

        xref_seq = cp.counterparty_last_seq
        xref_result["references_checked"] += 1

        # Referenced sequence must exist in target chain
        if xref_seq not in target_seq_set:
            xref_result["valid"] = False
            xref_result["violations"].append({
                "type": "MISSING_REFERENCE",
                "source": source_label,
                "source_sequence": record.chain.sequence_number,
                "referenced_target_sequence": xref_seq,
                "message": (
                    f"Agent {source_label} seq {record.chain.sequence_number} "
                    f"references Agent {target_label} seq {xref_seq}, "
                    f"but that sequence does not exist"
                ),
            })

        # Cross-references must be monotonically non-decreasing
        if last_xref is not None and xref_seq < last_xref:
            xref_result["valid"] = False
            xref_result["violations"].append({
                "type": "NON_MONOTONIC_REFERENCE",
                "source": source_label,
                "source_sequence": record.chain.sequence_number,
                "current_ref": xref_seq,
                "previous_ref": last_xref,
                "message": (
                    f"Agent {source_label} cross-reference went backwards: "
                    f"{last_xref} → {xref_seq}"
                ),
            })

        last_xref = xref_seq


def _check_amount_consistency(
    chain_a: List[AuditRecord],
    chain_b: List[AuditRecord],
    amount_result: Dict[str, Any],
) -> None:
    """Check that monetary amounts are consistent between chains.

    Compares amounts in settlement-phase records across chains.
    For each amount field (amount, total_value, price), collects the
    LAST value seen in each chain's settlement records, then compares.

    This handles the bilateral single-chain perspective: Alice records
    PAYMENT_SENT with amount=65, Bob records PAYMENT_CONFIRMED with
    amount=65. Different audit_point_types, same field, same value.
    """
    AMOUNT_FIELDS = ("amount", "total_value", "price")
    SETTLEMENT_TYPES = {
        AuditPointType.AGREEMENT_OR_REJECTION,
        AuditPointType.PAYMENT_SENT,
        AuditPointType.PAYMENT_CONFIRMED,
    }

    def _extract_settlement_amounts(chain: List[AuditRecord]) -> Dict[str, float]:
        """Extract the last settlement amount per field from a chain."""
        amounts: Dict[str, float] = {}
        for record in chain:
            if record.header.audit_point_type in SETTLEMENT_TYPES:
                sd = record.structured_data
                for field in AMOUNT_FIELDS:
                    if field in sd and isinstance(sd[field], (int, float)):
                        # Last-write wins: later records override earlier
                        amounts[field] = float(sd[field])
        return amounts

    amounts_a = _extract_settlement_amounts(chain_a)
    amounts_b = _extract_settlement_amounts(chain_b)

    # Find shared fields and check for mismatches
    shared_fields = set(amounts_a.keys()) & set(amounts_b.keys())
    for field in shared_fields:
        val_a = amounts_a[field]
        val_b = amounts_b[field]
        # Use tolerance for floating-point comparison
        if abs(val_a - val_b) > 0.001:
            amount_result["valid"] = False
            amount_result["violations"].append({
                "type": "AMOUNT_MISMATCH",
                "field": field,
                "agent_a_value": val_a,
                "agent_b_value": val_b,
                "message": (
                    f"Amount mismatch on '{field}': "
                    f"Agent A={val_a}, Agent B={val_b}"
                ),
            })


# ---------------------------------------------------------------------------
# Reviewer class (original methods preserved, new methods added)
# ---------------------------------------------------------------------------

class Reviewer:
    """AATP Reviewer — verifies and reviews audit records.

    Operates independently from the agent's recorder.  Has its own
    DID, private key, and review chain in storage.

    Args:
        auditor_did:         W3C DID of the auditor.
        auditor_private_key: Ed25519 private key for signing reviews.
        storage:             Storage backend (shared DB, separate tables).
    """

    def __init__(
        self,
        auditor_did: str,
        auditor_private_key: Ed25519PrivateKey,
        storage: Storage,
    ) -> None:
        self.auditor_did = auditor_did
        self.auditor_private_key = auditor_private_key
        self.storage = storage

    # ------------------------------------------------------------------
    # Level 1: Integrity verification
    # ------------------------------------------------------------------

    def verify_chain(
        self,
        agent_did: str,
        agent_public_key: Ed25519PublicKey,
        time_from: str = "",
        time_to: str = "",
    ) -> Dict[str, Any]:
        """Level 1: Integrity verification.

        Walks the agent's chain and verifies hashes, signatures,
        and chain links.

        Args:
            agent_did:        DID of the agent to verify.
            agent_public_key: Agent's public key for signature checks.
            time_from:        Optional ISO timestamp lower bound.
            time_to:          Optional ISO timestamp upper bound.

        Returns:
            L1 verification result dict with chain_valid, broken_links,
            invalid_records, timestamp_violations, sequence_gaps, and
            timestamp assurance metadata (semantic contract 7.3).
        """
        records = self.storage.get_agent_records(
            agent_did, time_from, time_to
        )
        result = core_verify_chain(records, agent_public_key)

        # Add timestamp assurance fields (semantic contract 7.3)
        result["record_timestamp_source"] = "local_clock"
        result["timestamp_assurance"] = "self_reported"
        result["anchor_verification"] = "na"

        return result

    # ------------------------------------------------------------------
    # Level 1 ext: Transition sequence verification
    # ------------------------------------------------------------------

    def verify_session_transitions(
        self,
        session_id: str,
    ) -> Dict[str, Any]:
        """Level 1 extension: Verify decision-point sequence for a session.

        Retrieves all records for the session and checks that the
        audit_point_type sequence follows the protocol's valid
        transition table.

        Args:
            session_id: Session to verify.

        Returns:
            Transition verification result dict.
        """
        records = self.storage.get_session_records(session_id)
        if not records:
            return {
                "transitions_valid": False,
                "violations": [{
                    "type": "NO_RECORDS",
                    "message": f"No records found for session {session_id}",
                }],
                "total_decision_records": 0,
            }
        return verify_transitions(records)

    # ------------------------------------------------------------------
    # Bilateral: Cross-chain verification
    # ------------------------------------------------------------------

    def verify_bilateral_session(
        self,
        chain_a: List[AuditRecord],
        chain_b: List[AuditRecord],
        public_key_a: Ed25519PublicKey,
        public_key_b: Ed25519PublicKey,
    ) -> Dict[str, Any]:
        """Bilateral cross-chain verification.

        Convenience method wrapping the module-level verify_bilateral().
        Accepts record lists directly (since bilateral sessions span
        two agents with separate storage).

        Args:
            chain_a:      All records from Agent A.
            chain_b:      All records from Agent B.
            public_key_a: Agent A's Ed25519 public key.
            public_key_b: Agent B's Ed25519 public key.

        Returns:
            Comprehensive bilateral verification result.
        """
        return verify_bilateral(chain_a, chain_b, public_key_a, public_key_b)

    # ------------------------------------------------------------------
    # Level 2: Conformance verification
    # ------------------------------------------------------------------

    def check_conformance(
        self,
        session_id: str,
        authorization_vc: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Level 2: Conformance verification.

        Checks:
        - VC hash matches initiation record (semantic contract 7.7)
        - Structured data within authorization limits
        - Narrative-structuredData consistency
        - Recorder flags summary
        - Purpose consistency across the session

        Args:
            session_id:       Session to check.
            authorization_vc: The authorization VC dict to verify against.

        Returns:
            L2 conformance result dict.
        """
        records = self.storage.get_session_records(session_id)
        if not records:
            return {"error": f"No records found for session {session_id}"}

        # Find initiation record
        initiation = next(
            (r for r in records
             if r.header.audit_point_type.value == "initiation"),
            None,
        )
        if not initiation:
            return {"error": "No initiation record found"}

        result: Dict[str, Any] = {
            "session_id": session_id,
            "vc_hash_match": False,
            "within_scope": True,
            "within_limits": True,
            "purpose_consistent": True,
            "narrative_consistency": 1.0,
            "recorder_flags_summary": [],
            "inconsistencies": [],
            "flagged_items": [],
        }

        # --- Semantic contract 7.7: Verify VC hash ---
        vc_canonical = canonicalize(authorization_vc)
        vc_hash = sha256_hex(vc_canonical)
        stored_vc_hash = initiation.authorization.authorization_vc_hash

        if stored_vc_hash and vc_hash == stored_vc_hash:
            result["vc_hash_match"] = True
        else:
            result["vc_hash_match"] = False
            result["within_scope"] = False
            result["flagged_items"].append({
                "issue": "VC_HASH_MISMATCH",
                "record_id": initiation.header.record_id,
                "expected": stored_vc_hash,
                "actual": vc_hash,
            })

        # --- Check each record ---
        inconsistency_count = 0
        total_checks = 0

        for record in records:
            sd = record.structured_data

            # Collect recorder flags
            rec_flags = sd.get("recorder_flags", [])
            if isinstance(rec_flags, list):
                for flag in rec_flags:
                    result["recorder_flags_summary"].append({
                        "flag": flag,
                        "record_id": record.header.record_id,
                    })
                    if flag == "PURPOSE_DRIFT":
                        result["purpose_consistent"] = False
                        result["flagged_items"].append({
                            "issue": "PURPOSE_DRIFT",
                            "record_id": record.header.record_id,
                        })

            # Check spending limits if VC specifies them
            max_val = (
                authorization_vc.get("max_transaction_value")
                or (authorization_vc.get("credential_subject", {})
                    .get("max_transaction_value"))
            )
            if max_val is not None:
                for key in ("amount", "total_value", "price", "monthly_cost"):
                    if key in sd:
                        val = sd[key]
                        if isinstance(val, (int, float)) and val > max_val:
                            result["within_limits"] = False
                            result["flagged_items"].append({
                                "issue": f"EXCEEDS_LIMIT:{key}",
                                "record_id": record.header.record_id,
                                "limit": max_val,
                                "actual": val,
                            })

            # Check category scope if VC specifies it
            allowed = (
                authorization_vc.get("allowed_categories")
                or (authorization_vc.get("credential_subject", {})
                    .get("allowed_categories"))
            )
            if allowed:
                category = sd.get("category", "")
                if category and category not in allowed:
                    result["within_scope"] = False
                    result["flagged_items"].append({
                        "issue": f"OUT_OF_SCOPE:{category}",
                        "record_id": record.header.record_id,
                    })

            # Narrative-structuredData consistency check
            total_checks += 1
            narrative_nums = set(
                float(m)
                for m in re.findall(
                    r"\$?([\d]+\.[\d]{2})(?:\b|[^.\d]|$)",
                    record.narrative,
                )
            )
            data_nums = set(
                float(v) for v in sd.values()
                if isinstance(v, (int, float))
            )
            for n in narrative_nums:
                if n not in data_nums:
                    inconsistency_count += 1
                    result["inconsistencies"].append({
                        "field": "amount",
                        "narrative_value": n,
                        "data_value": None,
                        "record_id": record.header.record_id,
                    })
                    break

        if total_checks > 0:
            result["narrative_consistency"] = round(
                1.0 - (inconsistency_count / total_checks), 2
            )

        return result

    # ------------------------------------------------------------------
    # Level 3 prep: Format for AI review
    # ------------------------------------------------------------------

    def get_session_for_review(
        self, session_id: str
    ) -> Dict[str, Any]:
        """Level 3 prep: Format session records for AI review.

        Returns all records with annotations, readable by audit AI.

        Args:
            session_id: Session to format.

        Returns:
            Dict with session metadata and annotated record list.
        """
        records = self.storage.get_session_records(session_id)
        if not records:
            return {"error": f"No records found for session {session_id}"}

        session_meta = self.storage.get_session(session_id)

        formatted: Dict[str, Any] = {
            "session_id": session_id,
            "purpose": session_meta["purpose"] if session_meta else "unknown",
            "mode": session_meta["mode"] if session_meta else "unknown",
            "status": session_meta["status"] if session_meta else "unknown",
            "total_records": len(records),
            "records": [],
        }

        for record in records:
            sd = record.structured_data
            entry: Dict[str, Any] = {
                "record_id": record.header.record_id,
                "sequence_number": record.chain.sequence_number,
                "audit_point_type": record.header.audit_point_type.value,
                "timestamp": record.header.timestamp.isoformat(),
                "narrative": record.narrative,
                "structured_data": sd,
            }

            # Build annotations
            annotations: List[str] = []

            # Recorder flags
            rec_flags = sd.get("recorder_flags", [])
            if isinstance(rec_flags, list):
                for flag in rec_flags:
                    annotations.append(f"\u26a0 Recorder flag: {flag}")

            # Narrative vs data consistency
            narrative_nums = set(
                float(m)
                for m in re.findall(
                    r"\$?([\d]+\.[\d]{2})(?:\b|[^.\d]|$)",
                    record.narrative,
                )
            )
            data_nums = set(
                float(v) for v in sd.values()
                if isinstance(v, (int, float))
            )
            for n in narrative_nums:
                if n not in data_nums:
                    annotations.append(
                        f"\u26a0 Narrative mentions ${n:.2f} "
                        f"but not found in structured_data"
                    )

            entry["annotations"] = annotations
            formatted["records"].append(entry)

        return formatted

    # ------------------------------------------------------------------
    # Level 3: Submit review
    # ------------------------------------------------------------------

    def submit_review(
        self,
        session_id: str,
        overall_score: int,
        integrity_score: int,
        conformance_score: int,
        reasonableness_score: int,
        findings: List[Dict[str, Any]],
        recommendations: List[str],
    ) -> Dict[str, Any]:
        """Level 3: Store audit review.

        Creates a signed review record in the auditor's independent
        chain (semantic contract 7.8).

        Args:
            session_id:            Session being reviewed.
            overall_score:         0-100 overall audit score.
            integrity_score:       0-100 chain integrity score.
            conformance_score:     0-100 authorization conformance score.
            reasonableness_score:  0-100 decision reasonableness score.
            findings:              List of finding dicts, each MUST have
                                   record_refs (semantic contract 7.6).
            recommendations:       List of recommendation strings.

        Returns:
            Dict with review_id, record_hash, signature.

        Raises:
            ValueError: If findings lack record_refs or scores invalid.
        """
        # Validate findings have record_refs (semantic contract 7.6)
        for f in findings:
            if not f.get("record_refs") or not isinstance(f["record_refs"], list):
                raise ValueError(
                    f"Finding missing record_refs (semantic contract 7.6): "
                    f"{f.get('finding', 'unknown')}"
                )

        # Validate scores
        for name, score in [
            ("overall", overall_score),
            ("integrity", integrity_score),
            ("conformance", conformance_score),
            ("reasonableness", reasonableness_score),
        ]:
            if not (0 <= score <= 100):
                raise ValueError(f"{name}_score must be 0-100, got {score}")

        review_id = uuid7()

        # Get auditor's chain state
        auditor_state = self.storage.get_review_chain_state(self.auditor_did)
        prev_hash = (
            auditor_state["last_record_hash"] if auditor_state else None
        )
        last_seq = (
            auditor_state["last_sequence_number"] if auditor_state else -1
        )

        review: Dict[str, Any] = {
            "review_id": review_id,
            "version": "0.1.0",
            "session_id": session_id,
            "auditor_did": self.auditor_did,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_score": overall_score,
            "integrity_score": integrity_score,
            "conformance_score": conformance_score,
            "reasonableness_score": reasonableness_score,
            "findings": findings,
            "recommendations": recommendations,
            "previous_hash": prev_hash,
        }

        # Compute hash (exclude record_hash and signature)
        review_canonical = canonicalize(review)
        review["record_hash"] = sha256_hex(review_canonical)

        # Sign with auditor's key (semantic contract 7.8)
        sig = sign_bytes(self.auditor_private_key, review_canonical)
        review["signature"] = {
            "algorithm": "Ed25519",
            "signer": self.auditor_did,
            "value": sig,
        }

        # Store in auditor's independent chain
        self.storage.save_review(review)
        self.storage.update_review_chain_state(
            self.auditor_did, review["record_hash"], last_seq + 1
        )

        return {
            "review_id": review_id,
            "record_hash": review["record_hash"],
            "signature": review["signature"],
        }
