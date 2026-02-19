#!/usr/bin/env python3
"""
AATP Bilateral Mode Demo — API Credits Negotiation

Demonstrates bilateral audit with two independent agents:
  1. Alice (buyer) and Bob (seller) each maintain independent chains
  2. They negotiate API credits price through offer/counter-offer
  3. Each decision is recorded with narrative + structured data
  4. Cross-references (counterparty_last_seq) link the two chains
  5. Bilateral verification checks both chains + cross-references
  6. Two independent trail files are exported (one per agent)

This demo uses AuditSession directly (not Recorder) to demonstrate
the full bilateral protocol including cross-reference threading.
In production, a bilateral-aware Recorder would manage this.

Run:
    python examples/demo_bilateral.py

Requirements:
    pip install pydantic cryptography

Zero external dependencies — no API keys, no network, no LLM.
Uses mock agent logic with pre-written decision templates.

Reference: AATP Execution Plan §2B.1, Conceptual Framework v0.44 §4.5
"""

import json
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.crypto import generate_keypair, public_key_to_did_key
from aatp_core.record import (
    AuditPointType,
    Authorization,
    Counterparty,
    OperatingMode,
)
from aatp_core.session import AuditSession
from aatp_reviewer import verify_bilateral


# ============================================================
# Scenario Configuration
# ============================================================

SCENARIO = {
    "description": "API Credits Bulk Purchase Negotiation",
    "item": "DataClean API credits",
    "quantity": 10000,
    "currency": "USDC",
    "bob_initial_price": 75.00,
    "bob_floor_price": 60.00,
    "alice_counter_price": 65.00,
    "agreed_price": 65.00,
    "market_data": {
        "avg_price_range": "$0.006–$0.008/credit",
        "sources_compared": 3,
    },
    "alice": {
        "principal_name": "Alice Chen",
        "principal_did": "did:example:alice-chen",
        "scope": "Purchase API services up to $100/transaction",
        "max_transaction": 100.0,
    },
    "bob": {
        "principal_name": "Bob Martinez",
        "principal_did": "did:example:bob-martinez",
        "scope": "Sell API credits, min $0.006/credit, max 50000/batch",
        "min_unit_price": 0.006,
    },
}


# ============================================================
# Pretty-print helpers
# ============================================================

ICONS = {
    "initiation": "🟢",
    "termination": "🏁",
    "opening": "📂",
    "offer": "💬",
    "counter_offer": "↩️",
    "agreement_or_rejection": "🤝",
    "payment_sent": "💰",
    "payment_confirmed": "✅",
    "closing": "📦",
    "problem_or_dispute": "⚠️",
}


def print_header(text: str, char: str = "━", width: int = 72) -> None:
    print(f"\n{char * width}")
    print(f"  {text}")
    print(f"{char * width}")


def print_record(agent_name: str, record) -> None:
    """Print a formatted record summary."""
    apt = record.header.audit_point_type.value
    icon = ICONS.get(apt, "📌")
    ts = record.header.timestamp.strftime("%H:%M:%S")
    seq = record.chain.sequence_number

    narr = record.narrative
    if len(narr) > 76:
        narr = narr[:73] + "..."

    # Cross-reference info
    xref = ""
    cp = record.counterparty
    if cp and cp.counterparty_last_seq is not None:
        other = "Bob" if agent_name == "Alice" else "Alice"
        xref = f" (saw {other}[{cp.counterparty_last_seq}])"

    print(f"\n  [{agent_name[0]}:{seq}] {icon} {apt.upper()} | {ts}{xref}")
    print(f"        {narr}")

    sd = record.structured_data
    amount = sd.get("amount")
    if amount is not None:
        print(f"        ─── ${amount:.2f} {sd.get('currency', 'USD')} "
              f"| {sd.get('quantity', '?'):,} credits ───")


# ============================================================
# Bilateral Session Builder
# ============================================================

class BilateralAgent:
    """Wraps AuditSession with counterparty_last_seq tracking.

    Each agent maintains its own session. Before creating a record,
    the counterparty's latest sequence number is threaded in.
    """

    def __init__(
        self,
        name: str,
        principal_did: str,
        scope: str,
        private_key,
        agent_did: str,
        counterparty_did: str,
        purpose: str,
    ):
        self.name = name
        self.agent_did = agent_did
        self.counterparty_did = counterparty_did
        self._private_key = private_key
        self._last_counterparty_seq = None  # What we've seen from the other side

        # Create session — INITIATION is auto-sealed
        self.session = AuditSession(
            mode=OperatingMode.BILATERAL,
            authorization=Authorization(
                principal_did=principal_did,
                agent_did=agent_did,
                scope_summary=scope,
            ),
            private_key=private_key,
            initiation_narrative=f"Session initiated: {purpose}",
            initiation_data={
                "purpose": purpose,
                "mode": "bilateral",
                "counterparty": counterparty_did,
            },
            counterparty=Counterparty(counterparty_did=counterparty_did),
        )

    @property
    def last_seq(self) -> int:
        """Last sequence number in this agent's chain."""
        return self.session.last_record.chain.sequence_number

    def see_counterparty(self, other: "BilateralAgent") -> None:
        """Record that we've seen the counterparty's latest record."""
        self._last_counterparty_seq = other.last_seq

    def add_record(
        self,
        audit_point_type: str,
        narrative: str,
        structured_data: dict,
    ):
        """Add a record with current counterparty cross-reference."""
        # Build counterparty with cross-reference
        cp = Counterparty(
            counterparty_did=self.counterparty_did,
            counterparty_last_seq=self._last_counterparty_seq,
        )

        # Temporarily replace session counterparty to include xref
        self.session._counterparty = cp

        record = self.session.add_record(
            audit_point_type=AuditPointType(audit_point_type),
            narrative=narrative,
            structured_data=structured_data,
        )
        return record

    def close(self, narrative: str, structured_data: dict = None):
        """Close session with final counterparty cross-reference."""
        cp = Counterparty(
            counterparty_did=self.counterparty_did,
            counterparty_last_seq=self._last_counterparty_seq,
        )
        self.session._counterparty = cp

        return self.session.close(
            narrative=narrative,
            structured_data=structured_data,
        )

    @property
    def records(self):
        return self.session.records


# ============================================================
# Main Demo
# ============================================================

def main():
    S = SCENARIO

    print("=" * 72)
    print("  AATP Bilateral Mode Demo — API Credits Negotiation")
    print("  Auditable Agent Transaction Protocol v0.1.0")
    print("=" * 72)

    # --- Setup: Keys ---
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    alice_did = public_key_to_did_key(alice_pub)
    bob_did = public_key_to_did_key(bob_pub)

    print(f"\n  Alice (buyer):   {alice_did[:40]}...")
    print(f"  Bob (seller):    {bob_did[:40]}...")
    print(f"  Item:            {S['quantity']:,} {S['item']}")
    print(f"  Bob's ask:       ${S['bob_initial_price']:.2f}")
    print(f"  Alice's target:  ${S['alice_counter_price']:.2f}")

    # --- Setup: Bilateral Agents ---
    alice = BilateralAgent(
        name="Alice",
        principal_did=S["alice"]["principal_did"],
        scope=S["alice"]["scope"],
        private_key=alice_priv,
        agent_did=alice_did,
        counterparty_did=bob_did,
        purpose=f"Purchase {S['quantity']:,} {S['item']} from Bob's agent",
    )
    bob = BilateralAgent(
        name="Bob",
        principal_did=S["bob"]["principal_did"],
        scope=S["bob"]["scope"],
        private_key=bob_priv,
        agent_did=bob_did,
        counterparty_did=alice_did,
        purpose=f"Sell {S['quantity']:,} {S['item']} to Alice's agent",
    )

    # ============================================================
    # PHASE 1: SESSION INITIATION (auto-sealed by AuditSession)
    # ============================================================
    print_header("Phase 1 — Session Initiation")
    print_record("Alice", alice.records[-1])
    print_record("Bob", bob.records[-1])

    # ============================================================
    # PHASE 2: NEGOTIATION
    # ============================================================
    print_header("Phase 2 — Negotiation")

    # Step 1: Alice opens negotiation
    print(f"\n  ── Step 1: Alice opens negotiation")
    alice.see_counterparty(bob)   # Alice has seen Bob's INITIATION
    alice.add_record(
        audit_point_type="opening",
        narrative=(
            f"Initiating purchase negotiation for {S['quantity']:,} "
            f"{S['item']}. Authorized up to "
            f"${S['alice']['max_transaction']:.2f}/transaction. "
            f"Market research shows pricing range of "
            f"{S['market_data']['avg_price_range']}."
        ),
        structured_data={
            "action": "open_negotiation",
            "item": S["item"],
            "quantity": S["quantity"],
            "budget_limit": S["alice"]["max_transaction"],
            "market_range": S["market_data"]["avg_price_range"],
            "category": "api_services",
        },
    )
    print_record("Alice", alice.records[-1])

    # Step 2: Bob opens + makes offer (has seen Alice's opening)
    print(f"\n  ── Step 2: Bob opens and makes offer")
    bob.see_counterparty(alice)   # Bob has seen Alice's OPENING
    bob.add_record(
        audit_point_type="opening",
        narrative=(
            f"Responding to Alice's purchase inquiry for {S['quantity']:,} "
            f"{S['item']}. Preparing bulk pricing offer."
        ),
        structured_data={
            "action": "open_negotiation",
            "item": S["item"],
            "quantity": S["quantity"],
            "category": "api_services",
        },
    )
    print_record("Bob", bob.records[-1])

    bob.add_record(
        audit_point_type="offer",
        narrative=(
            f"Offering {S['quantity']:,} {S['item']} "
            f"at ${S['bob_initial_price']:.2f} "
            f"(${S['bob_initial_price']/S['quantity']:.4f}/credit). "
            f"Standard bulk pricing tier. "
            f"Includes 30-day validity and API key provisioning."
        ),
        structured_data={
            "action": "offer",
            "item": S["item"],
            "quantity": S["quantity"],
            "amount": S["bob_initial_price"],
            "unit_price": round(S["bob_initial_price"] / S["quantity"], 6),
            "currency": S["currency"],
            "validity_days": 30,
            "category": "api_services",
        },
    )
    print_record("Bob", bob.records[-1])

    # Step 3: Alice counter-offers (has seen Bob's offer)
    print(f"\n  ── Step 3: Alice counter-offers")
    alice.see_counterparty(bob)   # Alice has seen Bob's OFFER
    unit = S["alice_counter_price"] / S["quantity"]
    alice.add_record(
        audit_point_type="counter_offer",
        narrative=(
            f"Counter-proposing ${S['alice_counter_price']:.2f} for "
            f"{S['quantity']:,} {S['item']}. "
            f"Bob offered ${S['bob_initial_price']:.2f} "
            f"(${S['bob_initial_price']/S['quantity']:.4f}/credit). "
            f"Market data from {S['market_data']['sources_compared']} "
            f"comparable services shows average pricing of "
            f"{S['market_data']['avg_price_range']}. "
            f"Our counter of ${unit:.4f}/credit is within market range "
            f"and within my ${S['alice']['max_transaction']:.2f} limit."
        ),
        structured_data={
            "action": "counter_offer",
            "item": S["item"],
            "quantity": S["quantity"],
            "amount": S["alice_counter_price"],
            "unit_price": round(unit, 6),
            "currency": S["currency"],
            "original_offer": S["bob_initial_price"],
            "market_avg_range": S["market_data"]["avg_price_range"],
            "sources_compared": S["market_data"]["sources_compared"],
            "category": "api_services",
        },
    )
    print_record("Alice", alice.records[-1])

    # Step 4: Bob accepts (has seen Alice's counter)
    print(f"\n  ── Step 4: Bob accepts counter-offer")
    bob.see_counterparty(alice)   # Bob has seen Alice's COUNTER_OFFER
    price = S["agreed_price"]
    floor = S["bob_floor_price"]
    bob.add_record(
        audit_point_type="agreement_or_rejection",
        narrative=(
            f"Accepting counter-offer of ${price:.2f} "
            f"for {S['quantity']:,} {S['item']}. "
            f"Price ${price/S['quantity']:.4f}/credit is above our "
            f"floor of ${floor/S['quantity']:.4f}/credit. "
            f"Margin acceptable for bulk transaction. "
            f"Proceeding to payment settlement."
        ),
        structured_data={
            "action": "accept",
            "item": S["item"],
            "quantity": S["quantity"],
            "amount": price,
            "unit_price": round(price / S["quantity"], 6),
            "currency": S["currency"],
            "above_floor_by": round(price - floor, 2),
            "category": "api_services",
        },
    )
    print_record("Bob", bob.records[-1])

    # ============================================================
    # PHASE 3: SETTLEMENT
    # ============================================================
    print_header("Phase 3 — Settlement")

    # Step 5: Alice sends payment (has seen Bob's agreement)
    print(f"\n  ── Step 5: Alice sends payment")
    alice.see_counterparty(bob)   # Alice has seen Bob's AGREEMENT
    alice.add_record(
        audit_point_type="payment_sent",
        narrative=(
            f"Initiating payment of ${price:.2f} {S['currency']} "
            f"to Bob's agent for {S['quantity']:,} {S['item']}. "
            f"Amount matches agreed terms. "
            f"Payment method: {S['currency']} on-chain transfer."
        ),
        structured_data={
            "action": "payment_sent",
            "amount": price,
            "currency": S["currency"],
            "quantity": S["quantity"],
            "item": S["item"],
            "payment_method": "on_chain_transfer",
            "category": "api_services",
        },
    )
    print_record("Alice", alice.records[-1])

    # Step 6: Bob confirms payment (has seen Alice's payment)
    print(f"\n  ── Step 6: Bob confirms payment & delivers credits")
    bob.see_counterparty(alice)   # Bob has seen Alice's PAYMENT_SENT
    bob.add_record(
        audit_point_type="payment_confirmed",
        narrative=(
            f"Payment of ${price:.2f} {S['currency']} received. "
            f"Delivering {S['quantity']:,} {S['item']} to buyer. "
            f"API key provisioned and access granted. "
            f"Transaction receipt: tx_mock_{int(price*100):06d}."
        ),
        structured_data={
            "action": "payment_confirmed",
            "amount": price,
            "currency": S["currency"],
            "quantity": S["quantity"],
            "item": S["item"],
            "tx_receipt": f"tx_mock_{int(price*100):06d}",
            "credits_delivered": True,
            "category": "api_services",
        },
    )
    print_record("Bob", bob.records[-1])

    # ============================================================
    # PHASE 4: CLOSING
    # ============================================================
    print_header("Phase 4 — Closing")

    # Step 7: Alice closing (has seen Bob's confirmation)
    print(f"\n  ── Step 7: Alice closes")
    alice.see_counterparty(bob)   # Alice has seen Bob's PAYMENT_CONFIRMED
    savings = S["bob_initial_price"] - price
    alice.add_record(
        audit_point_type="closing",
        narrative=(
            f"Transaction complete. Purchased {S['quantity']:,} "
            f"{S['item']} at ${price:.2f} "
            f"(${price/S['quantity']:.4f}/credit). "
            f"Original offer ${S['bob_initial_price']:.2f}; "
            f"negotiated ${savings:.2f} savings. "
            f"Payment confirmed by counterparty."
        ),
        structured_data={
            "action": "closing",
            "amount": price,
            "quantity": S["quantity"],
            "unit_price": round(price / S["quantity"], 6),
            "savings_from_negotiation": savings,
            "category": "api_services",
        },
    )
    print_record("Alice", alice.records[-1])

    # Step 8: Bob closing (has seen Alice's closing)
    print(f"\n  ── Step 8: Bob closes")
    bob.see_counterparty(alice)   # Bob has seen Alice's CLOSING
    bob.add_record(
        audit_point_type="closing",
        narrative=(
            f"Transaction complete. Sold {S['quantity']:,} "
            f"{S['item']} at ${price:.2f} "
            f"(${price/S['quantity']:.4f}/credit). "
            f"Payment received and credits delivered. "
            f"No outstanding obligations."
        ),
        structured_data={
            "action": "closing",
            "amount": price,
            "quantity": S["quantity"],
            "unit_price": round(price / S["quantity"], 6),
            "credits_delivered": True,
            "outstanding_obligations": None,
            "category": "api_services",
        },
    )
    print_record("Bob", bob.records[-1])

    # --- Termination ---
    alice.see_counterparty(bob)
    alice.close(
        narrative=(
            f"Session completed: Purchased {S['quantity']:,} {S['item']} "
            f"at ${price:.2f}. Negotiated ${savings:.2f} below initial offer."
        ),
    )
    bob.see_counterparty(alice)
    bob.close(
        narrative=(
            f"Session completed: Sold {S['quantity']:,} {S['item']} "
            f"at ${price:.2f}. Credits delivered, payment confirmed."
        ),
    )
    print_record("Alice", alice.records[-1])
    print_record("Bob", bob.records[-1])

    # ============================================================
    # PHASE 5: BILATERAL VERIFICATION
    # ============================================================
    a_records = alice.records
    b_records = bob.records

    print_header("Bilateral Audit Verification")
    print(f"\n  Alice chain: {len(a_records)} records | session {alice.session.session_id[:12]}...")
    print(f"  Bob chain:   {len(b_records)} records | session {bob.session.session_id[:12]}...")

    result = verify_bilateral(
        chain_a=a_records,
        chain_b=b_records,
        public_key_a=alice_pub,
        public_key_b=bob_pub,
    )

    # --- L1: Integrity ---
    print_header("Level 1 — Integrity", "─")
    for label, key in [("Alice", "agent_a"), ("Bob", "agent_b")]:
        l1 = result[key]["l1_integrity"]
        total = l1["total_records"]
        status = "✓ intact" if l1["chain_valid"] else "✗ BROKEN"
        print(f"  {label} chain: {status} ({total} records)")

    # --- Transitions ---
    print_header("Level 1 ext — Decision Sequence", "─")
    for label, key in [("Alice", "agent_a"), ("Bob", "agent_b")]:
        tr = result[key]["transitions"]
        status = "✓ valid" if tr["transitions_valid"] else "✗ INVALID"
        print(f"  {label} transitions: {status} ({tr['total_decision_records']} decision points)")
        if not tr["transitions_valid"]:
            for v in tr["violations"]:
                print(f"    ✗ {v['message']}")

    # --- Cross-references ---
    xr = result["cross_reference"]
    print_header("Cross-Reference Verification", "─")
    status = "✓ complete" if xr["valid"] else "✗ GAPS DETECTED"
    print(f"  Status: {status} ({xr['references_checked']} references checked)")
    if not xr["valid"]:
        for v in xr["violations"]:
            print(f"    ✗ {v['message']}")

    # Print cross-reference trace
    print(f"\n  Cross-reference trace:")
    for records, name in [(a_records, "Alice"), (b_records, "Bob")]:
        for rec in records:
            cp = rec.counterparty
            if cp and cp.counterparty_last_seq is not None:
                apt = rec.header.audit_point_type.value
                seq = rec.chain.sequence_number
                other = "Bob" if name == "Alice" else "Alice"
                print(
                    f"    {name}[{seq}] {apt} → "
                    f"saw {other}[{cp.counterparty_last_seq}]"
                )

    # --- Amount consistency ---
    amt = result["amount_consistency"]
    print_header("Amount Consistency", "─")
    status = "✓ consistent" if amt["valid"] else "✗ MISMATCH"
    print(f"  Status: {status}")
    if not amt["valid"]:
        for v in amt["violations"]:
            print(f"    ✗ {v['message']}")

    # ============================================================
    # FINAL VERDICT
    # ============================================================
    l1_a = "✓" if result["agent_a"]["l1_integrity"]["chain_valid"] else "✗"
    l1_b = "✓" if result["agent_b"]["l1_integrity"]["chain_valid"] else "✗"
    tr_a = "✓" if result["agent_a"]["transitions"]["transitions_valid"] else "✗"
    tr_b = "✓" if result["agent_b"]["transitions"]["transitions_valid"] else "✗"
    xr_s = "✓" if result["cross_reference"]["valid"] else "✗"
    am_s = "✓" if result["amount_consistency"]["valid"] else "✗"
    overall = "✓ BILATERAL VERIFIED" if result["bilateral_valid"] else "✗ VERIFICATION FAILED"

    print(f"\n{'━' * 72}")
    print(f"  VERIFICATION SUMMARY")
    print(f"{'━' * 72}")
    print(f"  {l1_a} Alice L1 integrity     {l1_b} Bob L1 integrity")
    print(f"  {tr_a} Alice transitions       {tr_b} Bob transitions")
    print(f"  {xr_s} Cross-references        {am_s} Amount consistency")
    print(f"{'━' * 72}")
    print(f"  {overall}")
    print(f"  Level 3 (Reasonableness): requires auditor — not in automated demo")
    print(f"{'━' * 72}")

    # ============================================================
    # EXPORT TRAILS
    # ============================================================
    output_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "output"
    )
    os.makedirs(output_dir, exist_ok=True)

    for records, name in [(a_records, "alice"), (b_records, "bob")]:
        trail_path = os.path.join(output_dir, f"trail_{name}.json")
        trail_data = [json.loads(rec.model_dump_json()) for rec in records]
        with open(trail_path, "w", encoding="utf-8") as f:
            json.dump(trail_data, f, indent=2, ensure_ascii=False)
        print(f"\n  {name.capitalize()} trail: {trail_path}")

    print(f"\n  View trails:")
    print(f"    python -m tools.aatp_cli view examples/output/trail_alice.json")
    print(f"    python -m tools.aatp_cli view examples/output/trail_bob.json")


if __name__ == "__main__":
    main()
