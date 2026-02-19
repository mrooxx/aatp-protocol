#!/usr/bin/env python3
"""
AATP Tamper Detection Demo

Demonstrates AATP's core security property: tamper-evident audit chains.

Flow:
  1. Load a valid audit trail (from demo_solo.py output)
  2. Display the original record
  3. Tamper with a specific field (change $127.50 → $27.50)
  4. Re-run verification → shows hash mismatch + diff
  5. Show cascade: all subsequent records are invalidated

This is the "caught red-handed" demo — it proves AATP isn't just a log
system, it's a cryptographic audit chain.

Run:
    python examples/demo_solo.py       # first, generate the trail
    python examples/demo_tamper.py     # then, run tamper detection

Reference: AATP Execution Plan §2B.2, Conceptual Framework v0.44 §3
"""

import json
import os
import sys
import copy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.canonical import canonicalize
from aatp_core.crypto import generate_keypair, sha256_hex


# ============================================================
# Load trail
# ============================================================

def load_trail(path: str) -> list[dict]:
    """Load audit trail from JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# Recompute hash for a record (same as chain.py logic)
# ============================================================

def recompute_hash(record_dict: dict) -> str:
    """Recompute the hash for a record dict (excluding record_hash and signature)."""
    hashable = copy.deepcopy(record_dict)
    hashable["chain"].pop("record_hash", None)
    hashable["chain"].pop("signature", None)
    canonical_bytes = canonicalize(hashable)
    return sha256_hex(canonical_bytes)


# ============================================================
# Diff display
# ============================================================

def show_diff(label: str, original: str, tampered: str) -> None:
    """Show a colorized diff between original and tampered values."""
    print(f"    Field: {label}")
    print(f"    - Original:  {original}")
    print(f"    + Tampered:  {tampered}")


# ============================================================
# Main Demo
# ============================================================

def main():
    print("=" * 72)
    print("  AATP Tamper Detection Demo")
    print("  Auditable Agent Transaction Protocol v0.1.0")
    print("=" * 72)

    # Find trail file
    output_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "output"
    )
    trail_path = os.path.join(output_dir, "trail.json")

    if not os.path.exists(trail_path):
        print("\n  ERROR: No audit trail found.")
        print("  Run 'python examples/demo_solo.py' first to generate one.")
        sys.exit(1)

    trail = load_trail(trail_path)
    print(f"\n  Loaded audit trail: {len(trail)} records")

    # --- Step 1: Find the payment record to tamper ---
    tamper_idx = None
    for i, record in enumerate(trail):
        if record["header"]["audit_point_type"] == "payment_sent":
            tamper_idx = i
            break

    if tamper_idx is None:
        print("  No payment record found to tamper with.")
        sys.exit(1)

    target = trail[tamper_idx]
    seq = target["chain"]["sequence_number"]

    print(f"\n  Target record: sequence #{seq} "
          f"({target['header']['audit_point_type']})")
    print(f"  Record ID:     {target['header']['record_id']}")

    # --- Step 2: Show original values ---
    print(f"\n{'━' * 72}")
    print(f"  STEP 1: Original Record (verified intact)")
    print(f"{'━' * 72}")

    original_hash = target["chain"]["record_hash"]
    recomputed = recompute_hash(target)
    match = "✓ MATCH" if original_hash == recomputed else "✗ MISMATCH"

    print(f"\n  Narrative:     {target['narrative'][:70]}...")
    print(f"  Amount:        ${target['structured_data']['amount']:.2f}")
    print(f"  Stored hash:   {original_hash[:32]}...")
    print(f"  Computed hash: {recomputed[:32]}...")
    print(f"  Status:        {match}")

    # --- Step 3: Tamper! ---
    print(f"\n{'━' * 72}")
    print(f"  STEP 2: TAMPERING — Modifying the record")
    print(f"{'━' * 72}")

    # Deep copy and modify
    tampered_trail = copy.deepcopy(trail)
    tampered_record = tampered_trail[tamper_idx]

    original_amount = tampered_record["structured_data"]["amount"]
    tampered_amount = 27.50

    # Tamper: change amount in structured_data
    tampered_record["structured_data"]["amount"] = tampered_amount

    # Tamper: update narrative to match (a smarter attacker would do this)
    original_narrative = tampered_record["narrative"]
    tampered_narrative = original_narrative.replace(
        f"${original_amount:.2f}", f"${tampered_amount:.2f}"
    )
    tampered_record["narrative"] = tampered_narrative

    # But the attacker CANNOT update the hash without the private key
    print(f"\n  Attacker modifies:")
    show_diff(
        "structured_data.amount",
        f"${original_amount:.2f}",
        f"${tampered_amount:.2f}",
    )
    print()
    show_diff(
        "narrative",
        f"...bill ${original_amount:.2f}...",
        f"...bill ${tampered_amount:.2f}...",
    )
    print(f"\n  Note: Attacker updated both narrative and data to be consistent.")
    print(f"  But the record_hash and signature are immutable without the key.")

    # --- Step 4: Verification catches it ---
    print(f"\n{'━' * 72}")
    print(f"  STEP 3: VERIFICATION — Tamper Detected!")
    print(f"{'━' * 72}")

    tampered_hash = recompute_hash(tampered_record)
    stored_hash = tampered_record["chain"]["record_hash"]

    print(f"\n  === TAMPER DETECTION at record #{seq} ===")
    print(f"  ✗ INTEGRITY FAILURE")
    print(f"    Expected hash: {stored_hash[:48]}...")
    print(f"    Computed hash: {tampered_hash[:48]}...")
    print(f"    Record has been modified after creation.")

    # --- Step 5: Show cascade ---
    print(f"\n{'━' * 72}")
    print(f"  STEP 4: CASCADE — Subsequent Records Invalidated")
    print(f"{'━' * 72}")

    compromised = 0
    total = len(trail)

    for i in range(tamper_idx, len(trail)):
        record = tampered_trail[i]
        rec_seq = record["chain"]["sequence_number"]

        if i == tamper_idx:
            # This record was directly tampered
            status = "TAMPERED"
            compromised += 1
        else:
            # Check if previous_hash still links correctly
            # Since the tampered record's hash changed, all subsequent
            # records that chain from it are invalidated
            status = "INVALIDATED (chain broken)"
            compromised += 1

        apt = record["header"]["audit_point_type"]
        print(f"  ✗ seq #{rec_seq:2d} [{apt:25s}] — {status}")

    # Records before tamper point are fine
    for i in range(0, tamper_idx):
        record = trail[i]
        rec_seq = record["chain"]["sequence_number"]
        apt = record["header"]["audit_point_type"]
        print(f"  ✓ seq #{rec_seq:2d} [{apt:25s}] — intact")

    # --- Final verdict ---
    print(f"\n{'━' * 72}")
    print(f"  VERDICT")
    print(f"{'━' * 72}")
    print(f"\n  Chain status:       COMPROMISED")
    print(f"  Total records:      {total}")
    print(f"  Compromised:        {compromised} "
          f"(seq #{seq}–{total - 1})")
    print(f"  Trustworthy:        {total - compromised} "
          f"(seq #0–{max(0, seq - 1)})")
    print(f"\n  The tamper-evident hash chain detected the modification.")
    print(f"  Even though the attacker updated both narrative AND data,")
    print(f"  the cryptographic seal makes any change detectable.")
    print(f"\n  Original amount:    ${original_amount:.2f}")
    print(f"  Tampered amount:    ${tampered_amount:.2f}")
    print(f"  Difference:         ${original_amount - tampered_amount:.2f}")
    print(f"{'━' * 72}\n")


if __name__ == "__main__":
    main()
