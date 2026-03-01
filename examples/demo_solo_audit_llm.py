"""
demo_solo_audit_llm.py — Stage 3.3: Independent LLM Auditor Demo

Loads the audit trail produced by Stage 3.2 (demo_solo_llm.py),
imports it into a fresh Storage, then runs an independent LLM auditor
through the complete L1 → L2 → L3 pipeline.

The auditor uses SEPARATE keys from the agent (Invariant 6).

Usage:
    python examples/demo_solo_audit_llm.py

Prerequisites:
    - examples/output/trail_llm.json must exist (run demo_solo_llm.py first)
    - .env file with OPENAI_API_KEY at project root

Output:
    - examples/output/audit_report.json  — full audit results
    - examples/output/auditor_raw.json   — raw LLM response + token usage
"""

import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aatp_core.crypto import public_key_to_did_key
from aatp_core.storage import Storage
from aatp_auditor import AuditLLM, import_trail_to_storage
from aatp_reviewer import Reviewer


# ─────────────────────────────────────────────────────────────────────
# did:key → Ed25519PublicKey recovery
# ─────────────────────────────────────────────────────────────────────
# In production, an auditor obtains the agent's public key via a
# DID resolver. For this demo, we decode did:key directly — it is
# self-certifying and encodes the raw public key bytes.
#
# Format: did:key:z{base58btc(0xed01 + 32-byte-raw-key)}

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def _base58btc_decode(encoded: str) -> bytes:
    """Decode a base58btc string to bytes."""
    n = 0
    for char in encoded:
        n = n * 58 + _BASE58_ALPHABET.index(char)

    # Determine byte length
    # Convert to bytes, handling the size
    byte_length = (n.bit_length() + 7) // 8
    result = n.to_bytes(byte_length, "big") if byte_length > 0 else b""

    # Restore leading zero bytes
    leading_zeros = 0
    for char in encoded:
        if char == _BASE58_ALPHABET[0]:
            leading_zeros += 1
        else:
            break

    return b"\x00" * leading_zeros + result


def recover_public_key_from_did(did: str) -> Ed25519PublicKey:
    """Recover an Ed25519 public key from a did:key identifier.

    Args:
        did: A did:key string (e.g., "did:key:z6Mk...").

    Returns:
        Ed25519PublicKey instance.

    Raises:
        ValueError: If the DID format is invalid.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Not a did:key with multibase 'z' prefix: {did}")

    # Strip "did:key:z" → base58btc encoded payload
    encoded = did[len("did:key:z"):]
    decoded = _base58btc_decode(encoded)

    # Verify and strip multicodec prefix (0xed01 = Ed25519 public key)
    if not decoded.startswith(_ED25519_MULTICODEC_PREFIX):
        raise ValueError(
            f"Expected Ed25519 multicodec prefix 0xed01, "
            f"got {decoded[:2].hex()}"
        )

    raw_key = decoded[len(_ED25519_MULTICODEC_PREFIX):]
    if len(raw_key) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(raw_key)}"
        )

    return Ed25519PublicKey.from_public_bytes(raw_key)


# ─────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────

TRAIL_PATH = os.path.join(
    os.path.dirname(__file__), "output", "trail_llm.json"
)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
AUDIT_REPORT_PATH = os.path.join(OUTPUT_DIR, "audit_report.json")
AUDITOR_RAW_PATH = os.path.join(OUTPUT_DIR, "auditor_raw.json")

# Temp DB for this demo (separate from agent's DB)
AUDIT_DB_PATH = os.path.join(OUTPUT_DIR, "audit_demo.db")


# ─────────────────────────────────────────────────────────────────────
# Authorization VC reconstruction
# ─────────────────────────────────────────────────────────────────────
# The VC must be IDENTICAL to what demo_solo_llm.py used, byte-for-byte,
# so the VC hash matches. We reconstruct it using the same
# make_authorization_vc() logic and the same world_state.json data.

def _load_world_state() -> dict:
    """Load world_state.json from examples/data/."""
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    path = os.path.join(data_dir, "world_state.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _make_authorization_vc(
    principal_did: str,
    agent_did: str,
    scope: dict,
) -> dict:
    """Reconstruct the authorization VC exactly as demo_solo_llm.py does."""
    return {
        "type": "AuthorizationCredential",
        "issuer": principal_did,
        "credential_subject": {
            "id": agent_did,
            "scope": scope["scope"],
            "max_transaction_value": scope["max_single_transaction"],
            "allowed_categories": scope["allowed_categories"],
            "monthly_budget_limit": scope["monthly_budget_limit"],
        },
        "expiration_date": "2027-01-01T00:00:00Z",
    }


def main():
    print("=" * 60)
    print("AATP Stage 3.3 — Independent LLM Auditor Demo")
    print("=" * 60)
    print()

    # ── Check prerequisites ──
    if not os.path.exists(TRAIL_PATH):
        print(f"ERROR: {TRAIL_PATH} not found.")
        print("Run demo_solo_llm.py first to generate the audit trail.")
        sys.exit(1)

    # ── Clean up previous demo DB ──
    if os.path.exists(AUDIT_DB_PATH):
        os.remove(AUDIT_DB_PATH)

    # ── Step 1: Generate auditor keys (independent from agent) ──
    print("[Setup] Generating auditor key pair (Invariant 6)...")
    auditor_private_key = Ed25519PrivateKey.generate()
    auditor_public_key = auditor_private_key.public_key()
    auditor_did = public_key_to_did_key(auditor_public_key)
    print(f"  Auditor DID: {auditor_did}")
    print()

    # ── Step 2: Import trail into storage ──
    print(f"[Import] Loading trail from {TRAIL_PATH}...")
    storage = Storage(db_path=AUDIT_DB_PATH)

    import_result = import_trail_to_storage(TRAIL_PATH, storage)
    session_id = import_result["session_id"]
    agent_did = import_result["agent_did"]
    print(f"  Session: {session_id}")
    print(f"  Agent DID: {agent_did}")
    print(f"  Records imported: {import_result['record_count']}")
    print()

    # ── Step 3: Reconstruct authorization VC (must match demo_solo_llm.py) ──
    print("[Setup] Reconstructing authorization VC...")
    world = _load_world_state()
    principal_did = import_result["principal_did"]
    authorization_vc = _make_authorization_vc(
        principal_did=principal_did,
        agent_did=agent_did,
        scope=world["authorization"],
    )

    # Verify VC hash matches what's in the trail
    from aatp_core.canonical import canonicalize
    from aatp_core.crypto import sha256_hex
    expected_vc_hash = sha256_hex(canonicalize(authorization_vc))
    trail_vc_hash = None
    with open(TRAIL_PATH, "r", encoding="utf-8") as f:
        trail_records = json.load(f)
        if trail_records:
            trail_vc_hash = trail_records[0].get(
                "authorization", {}
            ).get("authorization_vc_hash")
    if expected_vc_hash == trail_vc_hash:
        print(f"  VC hash verified: {expected_vc_hash[:16]}...")
    else:
        print(f"  WARNING: VC hash mismatch!")
        print(f"    Expected: {expected_vc_hash[:24]}...")
        print(f"    Trail:    {trail_vc_hash[:24] if trail_vc_hash else 'None'}...")
    print()

    # ── Step 4: Recover agent's public key for L1 verification ──
    # did:key is self-certifying — the public key is encoded in the DID.
    # In production, an auditor would use a DID resolver.
    print("[Setup] Recovering agent public key from did:key...")
    agent_public_key = recover_public_key_from_did(agent_did)

    # Verify round-trip: re-encode and compare
    reconstructed_did = public_key_to_did_key(agent_public_key)
    assert reconstructed_did == agent_did, (
        f"DID round-trip failed: {agent_did} != {reconstructed_did}"
    )
    print(f"  Agent public key recovered and verified.")
    print()

    # ── Step 5: Initialize Reviewer + AuditLLM ──
    print("[Setup] Initializing Reviewer and AuditLLM...")
    reviewer = Reviewer(
        auditor_did=auditor_did,
        auditor_private_key=auditor_private_key,
        storage=storage,
    )
    auditor = AuditLLM(reviewer=reviewer)
    print(f"  Model: {auditor.model}")
    print()

    # ── Step 6: Run the full audit ──
    print("[Audit] Starting L1 → L2 → L3 audit pipeline...")
    print("-" * 50)

    result = auditor.audit_session(
        session_id=session_id,
        agent_did=agent_did,
        agent_public_key=agent_public_key,
        authorization_vc=authorization_vc,
    )

    print("-" * 50)
    print()

    # ── Step 7: Display results ──
    print("=" * 60)
    print("AUDIT RESULTS")
    print("=" * 60)
    print()

    # L1
    l1 = result["l1_result"]
    print(f"L1 Chain Integrity:    {'PASS' if l1['chain_valid'] else 'FAIL'}")
    trans = result["l1_transitions"]
    print(f"L1 Transitions:        {'PASS' if trans['transitions_valid'] else 'FAIL'}")

    # L2
    l2 = result["l2_result"]
    print(f"L2 VC Hash:            {'PASS' if l2.get('vc_hash_match') else 'FAIL'}")
    print(f"L2 Within Scope:       {'PASS' if l2.get('within_scope') else 'FAIL'}")
    print(f"L2 Within Limits:      {'PASS' if l2.get('within_limits') else 'FAIL'}")
    print()

    # L3 Scores
    scores = result["l3_scores"]
    print("L3 Auditor Scores:")
    print(f"  Overall:             {scores['overall']}/100")
    print(f"  Integrity:           {scores['integrity']}/100")
    print(f"  Conformance:         {scores['conformance']}/100")
    print(f"  Reasonableness:      {scores['reasonableness']}/100")
    print()

    # L3 Findings
    findings = result["l3_findings"]
    print(f"L3 Findings ({len(findings)}):")
    for i, f in enumerate(findings, 1):
        severity = f["severity"].upper()
        print(f"  [{severity}] {f['finding']}")
        if f.get("recommendation"):
            print(f"         → {f['recommendation']}")
    print()

    # L3 Recommendations
    recs = result["l3_recommendations"]
    if recs:
        print(f"L3 Recommendations ({len(recs)}):")
        for r in recs:
            print(f"  • {r}")
        print()

    # Review chain
    submit = result["l3_submit_result"]
    print(f"Review ID:             {submit['review_id']}")
    print(f"Review Hash:           {submit['record_hash'][:16]}...")
    print(f"Signed by:             {submit['signature']['signer']}")
    print()

    # Token usage
    usage = result["token_usage"]
    print(f"Token Usage:           {usage['total_tokens']} total "
          f"({usage['prompt_tokens']} prompt + "
          f"{usage['completion_tokens']} completion)")

    # ── Step 8: Save outputs ──
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Audit report (serializable version)
    report = {
        "session_id": session_id,
        "agent_did": agent_did,
        "auditor_did": auditor_did,
        "l1_chain_valid": l1["chain_valid"],
        "l1_transitions_valid": trans["transitions_valid"],
        "l2_vc_hash_match": l2.get("vc_hash_match"),
        "l2_within_scope": l2.get("within_scope"),
        "l2_within_limits": l2.get("within_limits"),
        "l3_scores": scores,
        "l3_findings": findings,
        "l3_recommendations": recs,
        "review_id": submit["review_id"],
        "review_hash": submit["record_hash"],
    }
    with open(AUDIT_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nAudit report saved:    {AUDIT_REPORT_PATH}")

    # Raw LLM response
    auditor_raw = {
        "model": auditor.model,
        "raw_response": auditor.last_raw_response,
        "usage": auditor.last_usage,
    }
    with open(AUDITOR_RAW_PATH, "w", encoding="utf-8") as f:
        json.dump(auditor_raw, f, indent=2, ensure_ascii=False)
    print(f"Auditor raw response:  {AUDITOR_RAW_PATH}")

    # Clean up
    storage.close()
    print(f"\nDemo database:         {AUDIT_DB_PATH}")
    print()
    print("=" * 60)
    print("Stage 3.3 demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
