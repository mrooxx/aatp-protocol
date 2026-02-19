#!/usr/bin/env python3
"""
AATP Violation Detection Demo — Agent Exceeds Authorization

Demonstrates AATP Level 2 conformance detection:
  - Agent makes decisions that EXCEED its authorized scope
  - The audit chain itself is cryptographically intact (L1 ✓)
  - But conformance review catches the violations (L2 ✗)

This is NOT tampering (no one modified records after the fact).
This is the agent acting beyond its delegated authority — and the
audit system catching it.

Scenario:
  The agent is authorized for max $500 single transaction and only
  for specific categories. It violates both: buying $750 of stock
  and purchasing from an unauthorized category ("hardware").

Run:
    python examples/demo_violation.py

Reference: AATP Conceptual Framework v0.44 §5.2 (Level 2 Review)
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.crypto import generate_keypair, public_key_to_did_key, sha256_hex
from aatp_core.canonical import canonicalize
from aatp_core.storage import Storage
from aatp_recorder import Recorder
from aatp_reviewer import Reviewer


# ============================================================
# Icons and formatting (shared with demo_solo)
# ============================================================

ICONS = {
    "initiation": "🟢", "termination": "🏁", "payment_sent": "💰",
    "closing": "❌", "offer": "📋", "opening": "📈",
    "agreement_or_rejection": "✅", "problem_or_dispute": "⚠️",
}


def print_header(text, char="━", width=72):
    print(f"\n{char * width}")
    print(f"  {text}")
    print(f"{char * width}")


def print_record_summary(seq, record):
    apt = record.header.audit_point_type.value
    icon = ICONS.get(apt, "📌")
    ts = record.header.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    narr = record.narrative
    if len(narr) > 80:
        narr = narr[:77] + "..."
    print(f"\n  [{seq}] {icon} {apt.upper()} | {ts}")
    print(f"      {narr}")
    sd = record.structured_data
    amount = sd.get("amount") or sd.get("total_cost")
    if amount is not None:
        print(f"      ─── Data: {{amount: ${amount:.2f}}} ───")


def print_l1_result(result):
    print_header("Level 1 — Integrity Verification")
    total = result["total_records"]
    valid = result["chain_valid"]
    if valid:
        print(f"  ✓ Hash chain:   intact ({total}/{total} records verified)")
        print(f"  ✓ Signatures:   all valid")
        print(f"  ✓ Timestamps:   monotonically increasing")
        print(f"  ✓ Sequence:     continuous (0-{total - 1})")
    print(f"\n  Result: {'✓ PASS' if valid else '✗ FAIL'}")


def print_l2_result(result):
    print_header("Level 2 — Conformance Verification")
    vc_ok = result.get("vc_hash_match", False)
    scope_ok = result.get("within_scope", False)
    limits_ok = result.get("within_limits", False)
    purpose_ok = result.get("purpose_consistent", False)
    consistency = result.get("narrative_consistency", 0)

    print(f"  {'✓' if vc_ok else '✗'} VC hash:              {'match' if vc_ok else 'MISMATCH'}")
    print(f"  {'✓' if scope_ok else '✗'} Within scope:         {'yes' if scope_ok else 'NO — out of scope'}")
    print(f"  {'✓' if limits_ok else '✗'} Within limits:        {'yes' if limits_ok else 'NO — exceeds limits'}")
    print(f"  {'✓' if purpose_ok else '⚠'} Purpose consistent:   {'yes' if purpose_ok else 'DRIFT detected'}")
    print(f"  {'✓' if consistency >= 0.8 else '⚠'} Narrative-data match: {consistency:.0%}")

    flagged = result.get("flagged_items", [])
    if flagged:
        print(f"\n  ⚠ Violations detected ({len(flagged)}):")
        for item in flagged:
            issue = item["issue"]
            rec_id = item["record_id"][:16]
            if "limit" in item and "actual" in item:
                print(f"    ✗ {issue}")
                print(f"      Limit: ${item['limit']:.2f}  |  Actual: ${item['actual']:.2f}")
                print(f"      Record: {rec_id}...")
            else:
                print(f"    ✗ {issue} — record {rec_id}...")

    all_pass = vc_ok and scope_ok and limits_ok
    status = "✓ PASS" if all_pass else "✗ VIOLATIONS FOUND"
    print(f"\n  Result: {status}")


# ============================================================
# Main Demo
# ============================================================

def main():
    print("=" * 72)
    print("  AATP Violation Detection Demo — Agent Exceeds Authorization")
    print("  Auditable Agent Transaction Protocol v0.1.0")
    print("=" * 72)

    # --- Setup ---
    agent_private, agent_public = generate_keypair()
    auditor_private, auditor_public = generate_keypair()
    agent_did = public_key_to_did_key(agent_public)
    auditor_did = public_key_to_did_key(auditor_public)
    principal_did = "did:key:z6MkPrincipalAlice"

    # Authorization: max $500 per transaction, specific categories only
    auth_vc = {
        "type": "AuthorizationCredential",
        "issuer": principal_did,
        "credential_subject": {
            "id": agent_did,
            "scope": "Daily management of bills, subscriptions, and investments",
            "max_transaction_value": 500.00,
            "allowed_categories": ["bills", "subscriptions", "investments"],
            "monthly_budget_limit": 800.00,
        },
        "expiration_date": "2027-01-01T00:00:00Z",
    }
    auth_vc_hash = sha256_hex(canonicalize(auth_vc))

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    try:
        storage = Storage(db_path)
        recorder = Recorder(
            agent_did=agent_did,
            principal_did=principal_did,
            scope_summary="Daily management of bills, subscriptions, and investments",
            private_key=agent_private,
            storage=storage,
            authorization_vc_hash=auth_vc_hash,
        )

        print(f"\n  Authorization limits:")
        print(f"    Max single transaction:  $500.00")
        print(f"    Allowed categories:      bills, subscriptions, investments")
        print(f"    Monthly budget:          $800.00")

        # --- Start Session ---
        result = recorder.start_session(
            purpose=(
                "Daily management review: pay bills, manage subscriptions, "
                "evaluate investments"
            ),
            mode="solo",
        )
        session_id = result["session_id"]
        print_header(f"Session: {session_id[:16]}... | Mode: Solo")

        records = storage.get_session_records(session_id)
        print_record_summary(0, records[0])

        # --- Decision 1: Normal bill payment (within limits) ---
        print(f"\n  ── Event 1: Normal bill payment")
        recorder.record_decision(
            session_id=session_id,
            audit_point_type="payment_sent",
            narrative=(
                "Pay internet bill $89.99. Monthly recurring payment "
                "to Comcast. Within budget ($710.01 remaining)."
            ),
            structured_data={
                "action": "pay",
                "payee": "Comcast",
                "amount": 89.99,
                "category": "bills",
                "budget_remaining": 710.01,
            },
        )
        records = storage.get_session_records(session_id)
        print_record_summary(1, records[-1])

        # --- Decision 2: VIOLATION — exceeds $500 limit ---
        print(f"\n  ── Event 2: ⚠ Agent buys stock EXCEEDING $500 limit")
        recorder.record_decision(
            session_id=session_id,
            audit_point_type="payment_sent",
            narrative=(
                "Buy 4 shares of AAPL at $178.20 = $712.80. "
                "Stock dropped below cost basis, buying the dip. "
                "Transferred $750.00 from checking to cover purchase "
                "plus commission."
            ),
            structured_data={
                "action": "buy_stock",
                "ticker": "AAPL",
                "shares": 4,
                "price_per_share": 178.20,
                "amount": 750.00,
                "category": "investments",
                "reason": "below_cost_basis",
            },
        )
        records = storage.get_session_records(session_id)
        print_record_summary(2, records[-1])
        print(f"      ⚠ This exceeds the $500 transaction limit!")

        # --- Decision 3: VIOLATION — unauthorized category ---
        print(f"\n  ── Event 3: ⚠ Agent purchases from UNAUTHORIZED category")
        recorder.record_decision(
            session_id=session_id,
            audit_point_type="payment_sent",
            narrative=(
                "Purchase new mechanical keyboard $149.99 from Amazon. "
                "Current keyboard has intermittent key failure. "
                "Selected Keychron Q1 based on reliability reviews."
            ),
            structured_data={
                "action": "purchase",
                "item": "Keychron Q1 Mechanical Keyboard",
                "amount": 149.99,
                "vendor": "Amazon",
                "category": "hardware",
                "reason": "equipment_replacement",
            },
        )
        records = storage.get_session_records(session_id)
        print_record_summary(3, records[-1])
        print(f"      ⚠ 'hardware' is not in allowed categories!")

        # --- Decision 4: Normal subscription cancel ---
        print(f"\n  ── Event 4: Normal subscription cancellation")
        recorder.record_decision(
            session_id=session_id,
            audit_point_type="closing",
            narrative=(
                "Cancel unused DataSync Pro subscription ($9.99/mo). "
                "No usage in 187 days. Annual savings: $119.88."
            ),
            structured_data={
                "action": "cancel",
                "service": "DataSync Pro",
                "monthly_cost": 9.99,
                "last_used_days": 187,
                "annual_savings": 119.88,
                "category": "subscriptions",
            },
        )
        records = storage.get_session_records(session_id)
        print_record_summary(4, records[-1])

        # --- End Session ---
        recorder.end_session(
            session_id=session_id,
            outcome_summary=(
                "4 decisions processed. 2 payments made, 1 subscription "
                "cancelled, total spent $989.98."
            ),
            total_value=989.98,
        )
        records = storage.get_session_records(session_id)
        print_record_summary(5, records[-1])

        # --- Verification ---
        reviewer = Reviewer(
            auditor_did=auditor_did,
            auditor_private_key=auditor_private,
            storage=storage,
        )

        # Level 1 — chain integrity (should PASS — nothing was tampered)
        l1 = reviewer.verify_chain(agent_did, agent_public)
        print_l1_result(l1)

        # Level 2 — conformance (should FAIL — agent exceeded authority)
        l2 = reviewer.check_conformance(session_id, auth_vc)
        print_l2_result(l2)

        # --- Explanation ---
        print_header("What This Demonstrates")
        print(f"  Level 1 (Integrity) PASSED:")
        print(f"    The agent faithfully recorded everything it did.")
        print(f"    No records were modified after creation.")
        print(f"    The hash chain is cryptographically intact.")
        print()
        print(f"  Level 2 (Conformance) FAILED:")
        print(f"    The agent acted BEYOND its delegated authority:")
        print(f"    ✗ Transaction of $750.00 exceeds $500 limit")
        print(f"    ✗ Category 'hardware' is not in authorized scope")
        print()
        print(f"  Key insight:")
        print(f"    An honest but over-enthusiastic agent is different")
        print(f"    from a malicious actor tampering with records.")
        print(f"    AATP distinguishes between these two cases:")
        print(f"    - demo_tamper.py  → L1 fails (records altered)")
        print(f"    - demo_violation.py → L2 fails (agent exceeded scope)")
        print(f"{'━' * 72}\n")

        storage.close()
    finally:
        os.unlink(db_path)


if __name__ == "__main__":
    main()
