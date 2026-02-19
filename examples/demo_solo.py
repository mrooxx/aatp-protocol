#!/usr/bin/env python3
"""
AATP Solo Mode Demo — Personal Finance Agent

Demonstrates the full AATP audit lifecycle:
  1. Agent processes a queue of financial events
  2. Each decision is recorded with narrative + structured data
  3. Session is closed with outcome summary
  4. Level 1 (integrity) and Level 2 (conformance) verification runs
  5. Results printed in human-readable format

Run:
    python examples/demo_solo.py

Requirements:
    pip install pydantic cryptography

Zero external dependencies — no API keys, no network, no LLM.
Uses mock agent logic with pre-written templates (Stage 2A).

Reference: AATP Execution Plan §2A, Conceptual Framework v0.44 §4.5
"""

import json
import os
import sys
import tempfile

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.crypto import generate_keypair, public_key_to_did_key, sha256_hex
from aatp_core.canonical import canonicalize
from aatp_core.storage import Storage
from aatp_recorder import Recorder
from aatp_reviewer import Reviewer


# ============================================================
# Data loading
# ============================================================

def load_json(filename: str) -> dict | list:
    """Load JSON from examples/data/ directory."""
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    with open(os.path.join(data_dir, filename), "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# Mock Agent — deterministic decision logic (no LLM)
# ============================================================

class MockFinanceAgent:
    """Simple rule-based agent for demo purposes.

    In Stage 3, this will be replaced by a real LLM agent.
    For now, each event type has a deterministic decision rule.
    """

    def __init__(self, world_state: dict):
        self.world = world_state
        self.budget_remaining = world_state["finances"]["budget_remaining"]
        self.total_spent = 0.0
        self.savings_identified = 0.0
        self.pending_approval = []
        self.decisions_made = 0

    def process_event(self, event: dict) -> dict:
        """Process one event and return a decision dict.

        Returns:
            {
                "audit_point_type": str,
                "narrative": str,
                "structured_data": dict,
            }
        """
        handler = {
            "bill_received": self._handle_bill,
            "subscription_review": self._handle_subscription_review,
            "price_change": self._handle_price_change,
            "investment_opportunity": self._handle_investment,
            "schedule_conflict": self._handle_schedule_conflict,
            "new_service_offer": self._handle_new_service,
        }.get(event["type"])

        if handler is None:
            return {
                "audit_point_type": "extension",
                "narrative": f"Unknown event type: {event['type']}. Logged for review.",
                "structured_data": {"event": event, "action": "logged"},
                "extension_type": f"unknown_{event['type']}",
                "extension_justification": "Event type not covered by core decision points.",
            }

        return handler(event)

    def _handle_bill(self, event: dict) -> dict:
        d = event["data"]
        amount = d["amount"]

        if amount <= self.budget_remaining:
            self.budget_remaining -= amount
            self.total_spent += amount
            self.decisions_made += 1
            return {
                "audit_point_type": "payment_sent",
                "narrative": (
                    f"Pay bills — management review: {d['payee']} "
                    f"electricity ${amount:.2f}. Due {d['due_date']}. "
                    f"Amount within monthly budget "
                    f"(${self.budget_remaining:.2f} remaining). "
                    f"No pricing anomaly detected."
                ),
                "structured_data": {
                    "action": "pay",
                    "payee": d["payee"],
                    "amount": amount,
                    "currency": "USD",
                    "due_date": d["due_date"],
                    "budget_remaining": self.budget_remaining,
                    "category": d["category"],
                },
            }
        else:
            self.pending_approval.append(f"Bill ${amount:.2f} exceeds remaining budget")
            self.decisions_made += 1
            return {
                "audit_point_type": "problem_or_dispute",
                "narrative": (
                    f"Bill from {d['payee']} for ${amount:.2f} exceeds "
                    f"remaining monthly budget (${self.budget_remaining:.2f}). "
                    f"Flagged for principal approval."
                ),
                "structured_data": {
                    "action": "flag_for_approval",
                    "payee": d["payee"],
                    "amount": amount,
                    "budget_remaining": self.budget_remaining,
                    "reason": "exceeds_budget",
                    "category": d["category"],
                },
            }

    def _handle_subscription_review(self, event: dict) -> dict:
        d = event["data"]

        if d["last_used_days"] > 90 and not d.get("alternatives"):
            # Zero usage, no alternatives = cancel
            self.savings_identified += d["monthly_cost"]
            self.decisions_made += 1
            return {
                "audit_point_type": "closing",
                "narrative": (
                    f"Cancel {d['service']} subscription (${d['monthly_cost']:.2f}/mo). "
                    f"Zero usage in {d['last_used_days']} days. "
                    f"Annual savings: ${d['monthly_cost'] * 12:.2f}."
                ),
                "structured_data": {
                    "action": "cancel",
                    "service": d["service"],
                    "monthly_cost": d["monthly_cost"],
                    "last_used_days": d["last_used_days"],
                    "annual_savings": round(d["monthly_cost"] * 12, 2),
                    "category": d["category"],
                },
            }
        elif d.get("alternatives"):
            # Cheaper alternative found = flag for approval
            alt = d["alternatives"][0]
            savings = d["monthly_cost"] - alt["monthly_cost"]
            self.pending_approval.append(
                f"Switch {d['service']} → {alt['service']} (save ${savings:.2f}/mo)"
            )
            self.decisions_made += 1
            return {
                "audit_point_type": "offer",
                "narrative": (
                    f"Switch subscriptions: recommend changing from "
                    f"{d['service']} (${d['monthly_cost']:.2f}/mo) to "
                    f"{alt['service']} (${alt['monthly_cost']:.2f}/mo). "
                    f"Comparable features, saves ${savings:.2f}/mo "
                    f"(${savings * 12:.2f}/yr). "
                    f"Last used {d['service']}: {d['last_used_days']} days ago. "
                    f"Flagged for principal approval."
                ),
                "structured_data": {
                    "action": "recommend_switch",
                    "current_service": d["service"],
                    "current_cost": d["monthly_cost"],
                    "recommended_service": alt["service"],
                    "recommended_cost": alt["monthly_cost"],
                    "monthly_savings": round(savings, 2),
                    "annual_savings": round(savings * 12, 2),
                    "last_used_days": d["last_used_days"],
                    "category": d["category"],
                },
            }
        else:
            self.decisions_made += 1
            return {
                "audit_point_type": "agreement_or_rejection",
                "narrative": (
                    f"Retain {d['service']} (${d['monthly_cost']:.2f}/mo). "
                    f"Usage detected within acceptable range."
                ),
                "structured_data": {
                    "action": "retain",
                    "service": d["service"],
                    "monthly_cost": d["monthly_cost"],
                    "last_used_days": d["last_used_days"],
                    "category": d["category"],
                },
            }

    def _handle_price_change(self, event: dict) -> dict:
        d = event["data"]
        increase = d["new_price"] - d["current_price"]
        pct = (increase / d["current_price"]) * 100
        self.decisions_made += 1

        return {
            "audit_point_type": "agreement_or_rejection",
            "narrative": (
                f"Accept {d['service']} price increase: "
                f"${d['current_price']:.2f} → ${d['new_price']:.2f}/mo "
                f"(+{pct:.1f}%). Effective {d['effective_date']}. "
                f"Principal uses service actively (last used 3 days ago). "
                f"Increase within acceptable range (<25%)."
            ),
            "structured_data": {
                "action": "accept_price_change",
                "service": d["service"],
                "old_price": d["current_price"],
                "new_price": d["new_price"],
                "increase_pct": round(pct, 1),
                "effective_date": d["effective_date"],
                "category": d["category"],
            },
        }

    def _handle_investment(self, event: dict) -> dict:
        d = event["data"]
        self.pending_approval.append(
            f"Buy {d['ticker']} dip: ${d['suggested_amount']:.2f}"
        )
        self.decisions_made += 1

        return {
            "audit_point_type": "opening",
            "narrative": (
                f"Evaluate investment opportunity: {d['ticker']} dropped "
                f"to ${d['current_price']:.2f}, below average cost basis "
                f"${d['avg_cost']:.2f} ({d['shares_held']} shares held). "
                f"Opportunity to buy dip at ${d['suggested_amount']:.2f}. "
                f"However, this requires transferring funds from checking. "
                f"Flagged for principal approval — investment decisions "
                f"above $200 require explicit confirmation."
            ),
            "structured_data": {
                "action": "flag_for_approval",
                "ticker": d["ticker"],
                "current_price": d["current_price"],
                "avg_cost": d["avg_cost"],
                "shares_held": d["shares_held"],
                "suggested_amount": d["suggested_amount"],
                "reason": "requires_principal_approval",
                "category": d["category"],
            },
        }

    def _handle_schedule_conflict(self, event: dict) -> dict:
        d = event["data"]
        a = d["event_a"]
        b = d["event_b"]

        # Non-reschedulable takes priority
        if not a["reschedulable"] and b["reschedulable"]:
            priority, reschedule = a, b
        elif a["reschedulable"] and not b["reschedulable"]:
            priority, reschedule = b, a
        else:
            priority, reschedule = a, b  # default: keep first

        self.decisions_made += 1
        return {
            "audit_point_type": "agreement_or_rejection",
            "narrative": (
                f"Schedule conflict resolved: keep '{priority['name']}' "
                f"(non-reschedulable), reschedule '{reschedule['name']}'. "
                f"Client meeting takes priority over routine appointment."
            ),
            "structured_data": {
                "action": "resolve_conflict",
                "keep": priority["name"],
                "reschedule": reschedule["name"],
                "reason": "non_reschedulable_priority",
                "category": d["category"],
            },
        }

    def _handle_new_service(self, event: dict) -> dict:
        d = event["data"]
        self.decisions_made += 1

        return {
            "audit_point_type": "agreement_or_rejection",
            "narrative": (
                f"Decline new service offer: {d['service']} at "
                f"${d['monthly_cost']:.2f}/mo. "
                f"Current subscription load is already high "
                f"(5 active subscriptions). "
                f"No demonstrated need from principal's usage patterns. "
                f"Free trial period ({d['trial_period_days']} days) "
                f"does not justify onboarding overhead."
            ),
            "structured_data": {
                "action": "decline",
                "service": d["service"],
                "monthly_cost": d["monthly_cost"],
                "reason": "no_demonstrated_need",
                "current_subscription_count": 5,
                "category": d["category"],
            },
        }

    def get_outcome_summary(self) -> str:
        pending_str = (
            f" Items pending principal approval: {len(self.pending_approval)}."
            if self.pending_approval else ""
        )
        return (
            f"{self.decisions_made} decisions processed. "
            f"Total spent: ${self.total_spent:.2f}. "
            f"Monthly savings identified: ${self.savings_identified:.2f}/mo."
            f"{pending_str}"
        )


# ============================================================
# Authorization VC (mock)
# ============================================================

def make_authorization_vc(principal_did: str, agent_did: str, scope: dict) -> dict:
    """Create a mock authorization Verifiable Credential."""
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


# ============================================================
# Pretty-print helpers
# ============================================================

ICONS = {
    "initiation": "🟢",
    "termination": "🏁",
    "payment_sent": "💰",
    "closing": "❌",
    "offer": "📋",
    "opening": "📈",
    "agreement_or_rejection": "✅",
    "problem_or_dispute": "⚠️",
    "periodic_status": "📊",
    "extension": "🔧",
}


def print_header(text: str, char: str = "━", width: int = 72) -> None:
    print(f"\n{char * width}")
    print(f"  {text}")
    print(f"{char * width}")


def print_record_summary(seq: int, record) -> None:
    """Print a one-line summary of a record."""
    apt = record.header.audit_point_type.value
    icon = ICONS.get(apt, "📌")
    ts = record.header.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    # First line of narrative (truncated)
    narr = record.narrative
    if len(narr) > 80:
        narr = narr[:77] + "..."

    print(f"\n  [{seq}] {icon} {apt.upper()} | {ts}")
    print(f"      {narr}")

    # Show key structured_data fields
    sd = record.structured_data
    action = sd.get("action", "")
    amount = sd.get("amount") or sd.get("monthly_cost") or sd.get("suggested_amount")
    if action:
        detail = f"action={action}"
        if amount is not None:
            detail += f", ${amount:.2f}"
        print(f"      ─── Data: {{{detail}}} ───")


def print_l1_result(result: dict) -> None:
    """Print Level 1 verification results."""
    print_header("Level 1 — Integrity Verification")
    total = result["total_records"]
    valid = result["chain_valid"]

    if valid:
        print(f"  ✓ Hash chain:   intact ({total}/{total} records verified)")
        print(f"  ✓ Signatures:   all valid")
        print(f"  ✓ Timestamps:   monotonically increasing")
        print(f"  ✓ Sequence:     continuous (0-{total - 1})")
    else:
        print(f"  ✗ Chain integrity: FAILED")
        for bl in result.get("broken_links", []):
            print(f"    ✗ Broken link at seq {bl['sequence_number']}")
        for ir in result.get("invalid_records", []):
            print(f"    ✗ Invalid record at seq {ir['sequence_number']}: "
                  f"{', '.join(ir['errors'])}")
        for tv in result.get("timestamp_violations", []):
            print(f"    ✗ Timestamp violation at seq {tv['sequence_number']}")
        for sg in result.get("sequence_gaps", []):
            print(f"    ✗ Sequence gap: expected {sg['expected_sequence']}, "
                  f"got {sg['actual_sequence']}")

    status = "✓ PASS" if valid else "✗ FAIL"
    print(f"\n  Result: {status}")


def print_l2_result(result: dict) -> None:
    """Print Level 2 conformance results."""
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

    # Show flags
    flags = result.get("recorder_flags_summary", [])
    if flags:
        print(f"\n  Recorder flags ({len(flags)}):")
        for fl in flags:
            print(f"    ⚠ {fl['flag']} — record {fl['record_id'][:12]}...")

    # Show flagged items
    flagged = result.get("flagged_items", [])
    if flagged:
        print(f"\n  Flagged items ({len(flagged)}):")
        for item in flagged:
            print(f"    ⚠ {item['issue']} — record {item['record_id'][:12]}...")

    all_pass = vc_ok and scope_ok and limits_ok and purpose_ok and consistency >= 0.8
    status = "✓ PASS" if all_pass else "⚠ ISSUES FOUND"
    print(f"\n  Result: {status}")


# ============================================================
# Main Demo
# ============================================================

def main():
    print("=" * 72)
    print("  AATP Solo Mode Demo — Personal Finance Agent")
    print("  Auditable Agent Transaction Protocol v0.1.0")
    print("=" * 72)

    # --- Setup ---
    world = load_json("world_state.json")
    events = load_json("events.json")

    # Generate keys for agent and auditor
    agent_private, agent_public = generate_keypair()
    auditor_private, auditor_public = generate_keypair()

    agent_did = public_key_to_did_key(agent_public)
    auditor_did = public_key_to_did_key(auditor_public)
    principal_did = world["principal"]["did"]

    # Create authorization VC
    auth_vc = make_authorization_vc(
        principal_did=principal_did,
        agent_did=agent_did,
        scope=world["authorization"],
    )
    auth_vc_hash = sha256_hex(canonicalize(auth_vc))

    # Create temporary database
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    try:
        storage = Storage(db_path)

        # --- Initialize Recorder ---
        recorder = Recorder(
            agent_did=agent_did,
            principal_did=principal_did,
            scope_summary=world["authorization"]["scope"],
            private_key=agent_private,
            storage=storage,
            authorization_vc_hash=auth_vc_hash,
        )

        # --- Start Session ---
        print(f"\n  Agent DID:     {agent_did[:40]}...")
        print(f"  Principal:     {world['principal']['name']} ({principal_did})")
        print(f"  Mode:          Solo")
        print(f"  Events:        {len(events)}")

        result = recorder.start_session(
            purpose=(
                "Daily management review: pay bills, cancel or switch "
                "subscriptions, accept or decline price changes, evaluate "
                "investment opportunities, resolve scheduling conflicts, "
                "review new service offers"
            ),
            mode="solo",
        )
        session_id = result["session_id"]

        print_header(f"Session: {session_id[:12]}... | Mode: Solo", "━")

        # Print initiation
        records = storage.get_session_records(session_id)
        print_record_summary(0, records[0])

        # --- Process Events ---
        agent = MockFinanceAgent(world)

        for i, event in enumerate(events, start=1):
            print(f"\n  ── Event {i}/{len(events)}: {event['description']}")

            decision = agent.process_event(event)

            kwargs = {
                "session_id": session_id,
                "audit_point_type": decision["audit_point_type"],
                "narrative": decision["narrative"],
                "structured_data": decision["structured_data"],
            }
            if decision.get("extension_type"):
                kwargs["extension_type"] = decision["extension_type"]
                kwargs["extension_justification"] = decision["extension_justification"]

            rec_result = recorder.record_decision(**kwargs)

            # Print the record
            records = storage.get_session_records(session_id)
            print_record_summary(i, records[-1])

            if rec_result["recorder_flags"]:
                for flag in rec_result["recorder_flags"]:
                    print(f"      ⚠ RECORDER FLAG: {flag}")

        # --- End Session ---
        outcome = agent.get_outcome_summary()
        end_result = recorder.end_session(
            session_id=session_id,
            outcome_summary=outcome,
            total_value=agent.total_spent,
        )

        records = storage.get_session_records(session_id)
        print_record_summary(len(records) - 1, records[-1])

        # --- Periodic Status (summary) ---
        print_header("Session Summary")
        print(f"  Total records:       {end_result['total_records']}")
        print(f"  Total spent:         ${agent.total_spent:.2f}")
        print(f"  Savings identified:  ${agent.savings_identified:.2f}/mo")
        print(f"  Pending approval:    {len(agent.pending_approval)}")
        for item in agent.pending_approval:
            print(f"    • {item}")
        print(f"  Session digest:      {end_result['session_digest'][:24]}...")

        # --- Verification ---
        reviewer = Reviewer(
            auditor_did=auditor_did,
            auditor_private_key=auditor_private,
            storage=storage,
        )

        # Level 1
        l1 = reviewer.verify_chain(agent_did, agent_public)
        print_l1_result(l1)

        # Level 2
        l2 = reviewer.check_conformance(session_id, auth_vc)
        print_l2_result(l2)

        # Final banner
        l1_status = "✓ L1 PASS" if l1["chain_valid"] else "✗ L1 FAIL"
        l2_pass = (l2.get("vc_hash_match") and l2.get("within_scope")
                   and l2.get("within_limits"))
        l2_status = "✓ L2 PASS" if l2_pass else "⚠ L2 ISSUES"

        print(f"\n{'━' * 72}")
        print(f"  VERIFICATION: {l1_status} | {l2_status}")
        print(f"  Level 3 (Reasonableness): requires auditor — not in automated demo")
        print(f"{'━' * 72}")

        # --- Export audit trail for tamper demo ---
        output_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "output"
        )
        os.makedirs(output_dir, exist_ok=True)
        trail_path = os.path.join(output_dir, "trail.json")

        trail_data = []
        for rec in records:
            trail_data.append(json.loads(rec.model_dump_json()))

        with open(trail_path, "w", encoding="utf-8") as f:
            json.dump(trail_data, f, indent=2, ensure_ascii=False)

        print(f"\n  Audit trail exported: {trail_path}")
        print(f"  Run tamper demo:     python examples/demo_tamper.py")
        print(f"  View with CLI:       python -m tools.aatp_cli view {trail_path}")

        storage.close()

    finally:
        os.unlink(db_path)


if __name__ == "__main__":
    main()
