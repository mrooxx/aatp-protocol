"""
aatp_core/chain.py — AATP Hash Chain Management

Seal:   Set previous_hash → canonicalize → SHA-256 → Ed25519 sign
Verify: Walk chain, recompute hashes, check signatures and links

The chain is per-agent, cross-session. session_id provides the cross-cut.

Design adapted from v0.1 implementation with v2 Pydantic model integration.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize
from .crypto import sha256_hex, sign_bytes, verify_signature
from .record import AuditRecord, ChainMeta, Signature, validate_record_size


# ---------------------------------------------------------------------------
# Sealing (create hash + signature + chain link)
# ---------------------------------------------------------------------------

def seal_record(
    record: AuditRecord,
    private_key: Ed25519PrivateKey,
    previous_hash: Optional[str] = None,
) -> AuditRecord:
    """Seal a record: set previous_hash, compute record_hash, sign.

    This is the core deterministic operation of the protocol:
    1. Validate size (semantic contract 7.11)
    2. Set previous_hash (None for genesis, hash string for all others)
    3. Canonicalize hashable fields per RFC 8785
    4. Compute record_hash = SHA-256(canonical bytes)
    5. Sign canonical bytes with Ed25519

    Args:
        record: The record to seal. chain.sequence_number must already
                be set by the caller (session.py or recorder).
        private_key: Agent's Ed25519 private key.
        previous_hash: Hash of the previous record. None for genesis
                       (sequence_number=0).

    Returns:
        A new AuditRecord with chain fields populated.
        The original record is not mutated (Pydantic immutability).

    Raises:
        ValueError: If record exceeds 32KB (semantic contract 7.11),
                    or if previous_hash is inconsistent with sequence_number.
    """
    # Validate size limit (the ONE rejection case per 7.9/7.11)
    validate_record_size(record)

    # Validate genesis consistency
    seq = record.chain.sequence_number
    if seq == 0 and previous_hash is not None:
        raise ValueError(
            "Genesis record (sequence_number=0) must not have a previous_hash"
        )
    if seq > 0 and previous_hash is None:
        raise ValueError(
            "Non-genesis record must have a previous_hash"
        )

    # Step 1: Set previous_hash on a working copy
    # We use model_copy to produce a new record with updated chain fields,
    # preserving Pydantic validation.
    record_with_prev = record.model_copy(
        update={
            "chain": ChainMeta(
                sequence_number=seq,
                previous_hash=previous_hash,
                # record_hash and signature are not yet set
            )
        }
    )

    # Step 2: Canonicalize hashable fields
    hashable = record_with_prev.hashable_dict()
    canonical_bytes = canonicalize(hashable)

    # Step 3: Compute hash
    record_hash = sha256_hex(canonical_bytes)

    # Step 4: Sign canonical bytes
    sig_value = sign_bytes(private_key, canonical_bytes)
    signature = Signature(
        algorithm="Ed25519",
        signer=record.authorization.agent_did,
        value=sig_value,
    )

    # Step 5: Produce final sealed record
    sealed = record_with_prev.model_copy(
        update={
            "chain": ChainMeta(
                sequence_number=seq,
                previous_hash=previous_hash,
                record_hash=record_hash,
                signature=signature,
            )
        }
    )

    return sealed


# ---------------------------------------------------------------------------
# Single-record verification
# ---------------------------------------------------------------------------

def verify_record(
    record: AuditRecord,
    public_key: Ed25519PublicKey,
) -> dict:
    """Verify a single record's integrity.

    Checks:
    1. Recompute hash from canonical JSON → matches record_hash
    2. Signature is valid for the canonical bytes
    3. Signer matches authorization.agent_did (semantic contract 7.4)

    Returns dict with verification results.
    """
    result = {
        "record_id": record.header.record_id,
        "hash_valid": False,
        "signature_valid": False,
        "signer_match": False,
        "errors": [],
    }

    # Recompute hash
    hashable = record.hashable_dict()
    canonical_bytes = canonicalize(hashable)
    expected_hash = sha256_hex(canonical_bytes)

    if expected_hash == record.chain.record_hash:
        result["hash_valid"] = True
    else:
        result["errors"].append(
            f"Hash mismatch: computed {expected_hash}, "
            f"stored {record.chain.record_hash}"
        )

    # Verify signature
    sig = record.chain.signature
    if sig and sig.value:
        if verify_signature(public_key, canonical_bytes, sig.value):
            result["signature_valid"] = True
        else:
            result["errors"].append("Signature verification failed")
    else:
        result["errors"].append("No signature present")

    # Check signer identity (semantic contract 7.4)
    if sig and sig.signer == record.authorization.agent_did:
        result["signer_match"] = True
    elif sig:
        result["errors"].append(
            f"Signer mismatch: signature says {sig.signer}, "
            f"record says {record.authorization.agent_did}"
        )

    return result


# ---------------------------------------------------------------------------
# Chain verification (Level 1 integrity check)
# ---------------------------------------------------------------------------

def verify_chain(
    records: list[AuditRecord],
    public_key: Ed25519PublicKey,
) -> dict:
    """Verify an entire chain of records (Level 1 integrity check).

    Walks the chain in sequence order. For each record:
    - Verifies hash and signature (via verify_record)
    - Checks previous_hash links to prior record's record_hash
    - Checks timestamp monotonicity
    - Checks sequence_number continuity

    Returns Level 1 verification result.
    """
    result = {
        "chain_valid": True,
        "total_records": len(records),
        "broken_links": [],
        "invalid_records": [],
        "timestamp_violations": [],
        "sequence_gaps": [],
    }

    if not records:
        return result

    # Defensive sort by sequence_number
    records = sorted(records, key=lambda r: r.chain.sequence_number)

    prev_hash: Optional[str] = None  # Genesis expects None
    prev_timestamp: Optional[datetime] = None
    prev_seq: Optional[int] = None

    for record in records:
        seq = record.chain.sequence_number

        # --- Verify record integrity ---
        v = verify_record(record, public_key)
        if not v["hash_valid"] or not v["signature_valid"] or not v["signer_match"]:
            result["chain_valid"] = False
            result["invalid_records"].append({
                "record_id": record.header.record_id,
                "sequence_number": seq,
                "errors": v["errors"],
            })

        # --- Check chain link ---
        if record.chain.previous_hash != prev_hash:
            result["chain_valid"] = False
            result["broken_links"].append({
                "record_id": record.header.record_id,
                "sequence_number": seq,
                "expected_previous_hash": prev_hash,
                "actual_previous_hash": record.chain.previous_hash,
            })

        # --- Check timestamp monotonicity ---
        ts = record.header.timestamp
        if prev_timestamp is not None and ts < prev_timestamp:
            result["chain_valid"] = False
            result["timestamp_violations"].append({
                "record_id": record.header.record_id,
                "sequence_number": seq,
                "timestamp": ts.isoformat(),
                "previous_timestamp": prev_timestamp.isoformat(),
            })

        # --- Check sequence continuity ---
        if prev_seq is not None and seq != prev_seq + 1:
            result["chain_valid"] = False
            result["sequence_gaps"].append({
                "record_id": record.header.record_id,
                "expected_sequence": prev_seq + 1,
                "actual_sequence": seq,
            })

        # Advance: use STORED record_hash for next link
        # (If this record is tampered, the hash mismatch is already caught
        # by verify_record above. Using stored hash for linking means
        # chain-link verification reflects the original chain structure.)
        prev_hash = record.chain.record_hash
        prev_timestamp = ts
        prev_seq = seq

    return result


# ---------------------------------------------------------------------------
# Session digest
# ---------------------------------------------------------------------------

def compute_session_digest(records: list[AuditRecord]) -> str:
    """Compute digest of all records in a session.

    Concatenates all record_hash values in sequence order and hashes
    the result. Used in termination records for session-level integrity.
    """
    sorted_records = sorted(records, key=lambda r: r.chain.sequence_number)
    combined = "".join(
        r.chain.record_hash for r in sorted_records
        if r.chain.record_hash is not None
    )
    return sha256_hex(combined.encode("utf-8"))
