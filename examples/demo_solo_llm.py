#!/usr/bin/env python3
"""
AATP Solo Mode Demo — Real LLM Finance Agent (Purpose Chain)

Stage 3.2 deliverable (updated for Purpose Chain architecture):
  - Root session: LLM decomposes deployer objective into sub-goals
  - Downstream sessions: one per event, each with independent lifecycle
  - Purpose chain linkage via upstream_session_id in INITIATION records

Replaces the original single-session demo with a multi-session
architecture per Architecture Addendum v0.1 §2–3 and Notes 004.

Run:
    python examples/demo_solo_llm.py

Requirements:
    pip install pydantic cryptography openai python-dotenv
    Create .env file with: OPENAI_API_KEY=sk-your-key

Reference: AATP Execution Plan §3.2, Conceptual Framework v0.44 §4.5,
           Architecture Addendum v0.1, Stage 3 Notes 004
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
from aatp_agent import FinanceAgent, LLMResponseError


# ============================================================
# Data loading
# ============================================================

def load_json(filename: str) -> dict | list:
    """Load JSON from examples/data/ directory."""
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    with open(os.path.join(data_dir, filename), "r", encoding="utf-8") as f:
        return json.load(f)


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
    "initiation": "\U0001f7e2",
    "termination": "\U0001f3c1",
    "payment_sent": "\U0001f4b5",
    "closing": "\u274c",
    "offer": "\U0001f4cb",
    "opening": "\U0001f4c8",
    "agreement_or_rejection": "\u2705",
    "problem_or_dispute": "\u26a0\ufe0f",
    "periodic_status": "\U0001f4ca",
    "extension": "\U0001f527",
}


def print_header(text: str, char: str = "\u2500", width: int = 72) -> None:
    print(f"\n{char * width}")
    print(f"  {text}")
    print(f"{char * width}")


def print_record_summary(seq: int, record) -> None:
    """Print a one-line summary of a record."""
    apt = record.header.audit_point_type.value
    icon = ICONS.get(apt, "\U0001f4cc")
    ts = record.header.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    narr = record.narrative
    if len(narr) > 80:
        narr = narr[:77] + "..."

    print(f"\n  [{seq}] {icon} {apt.upper()} | {ts}")
    print(f"      {narr}")

    sd = record.structured_data
    action = sd.get("action", "")
    amount = sd.get("amount") or sd.get("monthly_cost") or sd.get("suggested_amount")
    if action:
        detail = f"action={action}"
        if amount is not None:
            detail += f", ${amount:.2f}"
        print(f"      \u2514\u2500\u2500 Data: {{{detail}}} \u2500\u2500\u2500")


def print_l1_result(result: dict) -> None:
    """Print Level 1 verification results."""
    print_header("Level 1 \u2014 Integrity Verification")
    total = result["total_records"]
    valid = result["chain_valid"]

    if valid:
        print(f"  \u2705 Hash chain:   intact ({total}/{total} records verified)")
        print(f"  \u2705 Signatures:   all valid")
        print(f"  \u2705 Timestamps:   monotonically increasing")
        print(f"  \u2705 Sequence:     continuous (0-{total - 1})")
    else:
        print(f"  \u274c Chain integrity: FAILED")
        for bl in result.get("broken_links", []):
            print(f"    \u274c Broken link at seq {bl['sequence_number']}")
        for ir in result.get("invalid_records", []):
            print(f"    \u274c Invalid record at seq {ir['sequence_number']}: "
                  f"{', '.join(ir['errors'])}")
        for tv in result.get("timestamp_violations", []):
            print(f"    \u274c Timestamp violation at seq {tv['sequence_number']}")
        for sg in result.get("sequence_gaps", []):
            print(f"    \u274c Sequence gap: expected {sg['expected_sequence']}, "
                  f"got {sg['actual_sequence']}")

    status = "\u2705 PASS" if valid else "\u274c FAIL"
    print(f"\n  Result: {status}")


def print_l2_result(session_label: str, result: dict) -> None:
    """Print Level 2 conformance results for one session."""
    vc_ok = result.get("vc_hash_match", False)
    scope_ok = result.get("within_scope", False)
    limits_ok = result.get("within_limits", False)
    purpose_ok = result.get("purpose_consistent", False)
    consistency = result.get("narrative_consistency", 0)

    ok = "\u2705"
    fail = "\u274c"
    warn = "\u26a0"

    all_pass = vc_ok and scope_ok and limits_ok and purpose_ok and consistency >= 0.8
    status_icon = ok if all_pass else warn

    print(f"  {status_icon} {session_label}: ", end="")
    issues = []
    if not vc_ok:
        issues.append("VC mismatch")
    if not scope_ok:
        issues.append("out of scope")
    if not limits_ok:
        issues.append("over limit")
    if not purpose_ok:
        issues.append("purpose drift")
    if consistency < 0.8:
        issues.append(f"narrative match {consistency:.0%}")

    if issues:
        print(", ".join(issues))
    else:
        print("PASS")

    flags = result.get("recorder_flags_summary", [])
    for fl in flags:
        print(f"    \u26a0\ufe0f {fl['flag']} \u2014 record {fl['record_id'][:12]}...")

    return all_pass


# ============================================================
# Main Demo
# ============================================================

def main():
    print("=" * 72)
    print("  AATP Solo Mode Demo \u2014 Purpose Chain Architecture")
    print("  Auditable Agent Transaction Protocol v0.1.0")
    print("  Model: gpt-4o-mini | Mode: Solo | Sessions: 1 root + N downstream")
    print("=" * 72)

    # --- Setup ---
    world = load_json("world_state.json")
    events = load_json("events.json")

    # Deployer objective — the human principal's instruction
    deployer_objective = (
        "Manage my personal finances for this review cycle. "
        "Pay due bills, review subscriptions for waste, handle "
        "price changes, evaluate investment opportunities, resolve "
        "scheduling conflicts, and decline unnecessary new services. "
        f"Monthly budget remaining: ${world['finances']['budget_remaining']:,.2f}."
    )

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

        # --- Initialize LLM Agent ---
        agent = FinanceAgent(world_state=world)

        # --- Print Setup Info ---
        print(f"\n  Agent DID:     {agent_did[:40]}...")
        print(f"  Principal:     {world['principal']['name']} ({principal_did})")
        print(f"  Mode:          Solo (Purpose Chain)")
        print(f"  Events:        {len(events)}")
        print(f"  LLM Model:     {agent.model}")

        # Track all session IDs for verification
        all_session_ids = []

        # ===========================================================
        # PHASE 1: Root Session — Goal Decomposition
        # ===========================================================

        print_header("Phase 1: Root Session \u2014 Goal Decomposition", "\u2550")

        # Generate plan via LLM
        print(f"\n  Deployer objective: {deployer_objective[:60]}...")
        print(f"  Calling LLM for goal decomposition...", end=" ", flush=True)

        try:
            plan = agent.generate_root_plan(deployer_objective, events)
            print("OK")
        except (LLMResponseError, Exception) as e:
            print(f"FAILED: {e}")
            print("  Cannot proceed without root plan. Exiting.")
            storage.close()
            return

        # Create root session via Recorder
        root_result = recorder.start_session(
            purpose="Goal decomposition: " + deployer_objective[:100],
            mode="solo",
            initiation_extra={
                "upstream_session_id": None,
                "deployer_objective": deployer_objective,
            },
        )
        root_session_id = root_result["session_id"]
        all_session_ids.append(root_session_id)

        print(f"\n  Root Session: {root_session_id[:16]}...")

        # Print INITIATION record
        root_records = storage.get_session_records(root_session_id)
        print_record_summary(0, root_records[0])

        # Record OPENING — the budget allocation plan
        recorder.record_decision(
            session_id=root_session_id,
            audit_point_type="opening",
            narrative=plan["plan_narrative"],
            structured_data={
                "action": "goal_decomposition",
                "allocations": plan["allocations"],
                "budget_summary": plan["budget_summary"],
                "total_sub_tasks": len(plan["allocations"]),
            },
        )

        root_records = storage.get_session_records(root_session_id)
        print_record_summary(1, root_records[-1])

        # Close root session
        recorder.end_session(
            session_id=root_session_id,
            outcome_summary=(
                f"Goal decomposition complete. "
                f"{len(plan['allocations'])} sub-tasks identified."
            ),
        )

        root_records = storage.get_session_records(root_session_id)
        print_record_summary(2, root_records[-1])

        # Build event_id → allocation lookup
        allocation_map = {}
        for alloc in plan["allocations"]:
            allocation_map[alloc["event_id"]] = alloc

        # ===========================================================
        # PHASE 2: Downstream Sessions — One Per Event
        # ===========================================================

        print_header(
            f"Phase 2: Downstream Sessions \u2014 {len(events)} Events",
            "\u2550",
        )

        for i, event in enumerate(events, start=1):
            event_id = event["event_id"]
            alloc = allocation_map.get(event_id)

            # Determine session purpose from root plan
            if alloc:
                session_purpose = alloc["purpose"]
            else:
                # Fallback if LLM missed an event in the plan
                session_purpose = f"Process event: {event['description']}"

            print_header(
                f"Session {i}/{len(events)}: {event['description'][:50]}",
            )

            # Start downstream session with purpose chain linkage
            ds_result = recorder.start_session(
                purpose=session_purpose,
                mode="solo",
                initiation_extra={
                    "upstream_session_id": root_session_id,
                    "deployer_objective": None,
                },
            )
            ds_session_id = ds_result["session_id"]
            all_session_ids.append(ds_session_id)

            # Print INITIATION
            ds_records = storage.get_session_records(ds_session_id)
            print_record_summary(0, ds_records[0])

            # Call LLM to process the event
            print(f"\n  Calling LLM...", end=" ", flush=True)

            try:
                decision = agent.process_event(
                    event, session_purpose=session_purpose
                )
                print("OK")
            except LLMResponseError as e:
                print(f"FAILED: {e}")
                # Close session with error
                recorder.end_session(
                    session_id=ds_session_id,
                    outcome_summary=f"Failed to process: {e}",
                )
                ds_records = storage.get_session_records(ds_session_id)
                print_record_summary(len(ds_records) - 1, ds_records[-1])
                continue
            except Exception as e:
                print(f"API ERROR: {e}")
                recorder.end_session(
                    session_id=ds_session_id,
                    outcome_summary=f"API error: {e}",
                )
                ds_records = storage.get_session_records(ds_session_id)
                print_record_summary(len(ds_records) - 1, ds_records[-1])
                continue

            # Record decision
            rec_result = recorder.record_decision(
                session_id=ds_session_id,
                audit_point_type=decision["audit_point_type"],
                narrative=decision["narrative"],
                structured_data=decision["structured_data"],
            )

            ds_records = storage.get_session_records(ds_session_id)
            print_record_summary(1, ds_records[-1])

            if rec_result["recorder_flags"]:
                for flag in rec_result["recorder_flags"]:
                    print(f"      \u26a0\ufe0f RECORDER FLAG: {flag}")

            # Close downstream session
            sd = decision["structured_data"]
            total_val = sd.get("amount") or sd.get("monthly_cost") or None
            recorder.end_session(
                session_id=ds_session_id,
                outcome_summary=(
                    f"{decision['structured_data'].get('action', 'processed')}: "
                    f"{event['description']}"
                ),
                total_value=total_val,
            )

            ds_records = storage.get_session_records(ds_session_id)
            print_record_summary(len(ds_records) - 1, ds_records[-1])

        # ===========================================================
        # PHASE 3: Summary and Verification
        # ===========================================================

        # --- Session Summary ---
        print_header("Session Summary")
        print(f"  Total sessions:      {len(all_session_ids)} "
              f"(1 root + {len(all_session_ids) - 1} downstream)")
        print(f"  Total spent:         ${agent.total_spent:.2f}")
        print(f"  Savings identified:  ${agent.savings_identified:.2f}/mo")
        print(f"  Pending approval:    {len(agent.pending_approval)}")
        for item in agent.pending_approval:
            print(f"    \u2022 {item}")

        # --- Token Usage ---
        print_header("LLM Token Usage")
        usage = agent.get_token_usage_summary()
        print(f"  Prompt tokens:     {usage['prompt_tokens']:,}")
        print(f"  Completion tokens: {usage['completion_tokens']:,}")
        print(f"  Total tokens:      {usage['total_tokens']:,}")
        print(f"  API calls:         {len(agent.llm_responses)} "
              f"(1 root + {len(agent.llm_responses) - 1} downstream)")

        # --- Level 1: Chain Integrity (global, once) ---
        reviewer = Reviewer(
            auditor_did=auditor_did,
            auditor_private_key=auditor_private,
            storage=storage,
        )

        l1 = reviewer.verify_chain(agent_did, agent_public)
        print_l1_result(l1)

        # --- Level 2: Conformance (per session) ---
        print_header("Level 2 \u2014 Conformance Verification (Per Session)")
        l2_all_pass = True
        for idx, sid in enumerate(all_session_ids):
            label = "ROOT" if idx == 0 else f"S{idx}"
            l2 = reviewer.check_conformance(sid, auth_vc)
            passed = print_l2_result(f"{label} ({sid[:12]}...)", l2)
            if not passed:
                l2_all_pass = False

        # --- Purpose Chain Summary ---
        print_header("Purpose Chain")
        print(f"  Root: {root_session_id[:16]}...")
        print(f"    deployer_objective: {deployer_objective[:60]}...")
        for idx, sid in enumerate(all_session_ids[1:], start=1):
            alloc = plan["allocations"][idx - 1] if idx - 1 < len(plan["allocations"]) else None
            purpose_str = alloc["purpose"][:50] if alloc else "unknown"
            print(f"    \u2514\u2500 S{idx}: {sid[:16]}... \u2014 {purpose_str}...")

        # --- Final Banner ---
        l1_status = "\u2705 L1 PASS" if l1["chain_valid"] else "\u274c L1 FAIL"
        l2_status = "\u2705 L2 PASS" if l2_all_pass else "\u26a0\ufe0f L2 ISSUES"

        line = "\u2500" * 72
        print(f"\n{line}")
        print(f"  VERIFICATION: {l1_status} | {l2_status}")
        print(f"  Sessions: {len(all_session_ids)} | "
              f"Purpose Chain: {'intact' if len(all_session_ids) > 1 else 'N/A'}")
        print(f"  Level 3 (Reasonableness): requires auditor LLM \u2014 see Stage 3.3")
        print(f"{line}")

        # --- Export audit trail ---
        output_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "output"
        )
        os.makedirs(output_dir, exist_ok=True)

        # Full audit trail (all sessions)
        trail_path = os.path.join(output_dir, "trail_llm.json")
        trail_data = []
        for sid in all_session_ids:
            session_records = storage.get_session_records(sid)
            for rec in session_records:
                trail_data.append(json.loads(rec.model_dump_json()))
        with open(trail_path, "w", encoding="utf-8") as f:
            json.dump(trail_data, f, indent=2, ensure_ascii=False)

        # Raw LLM responses (for debugging and audit)
        llm_path = os.path.join(output_dir, "llm_responses.json")
        with open(llm_path, "w", encoding="utf-8") as f:
            json.dump(agent.llm_responses, f, indent=2, ensure_ascii=False)

        # Purpose chain export
        chain_path = os.path.join(output_dir, "purpose_chain.json")
        chain_data = {
            "root_session_id": root_session_id,
            "deployer_objective": deployer_objective,
            "downstream_sessions": [
                {
                    "session_id": all_session_ids[i + 1],
                    "upstream_session_id": root_session_id,
                    "event_id": plan["allocations"][i]["event_id"],
                    "purpose": plan["allocations"][i]["purpose"],
                }
                for i in range(
                    min(len(plan["allocations"]), len(all_session_ids) - 1)
                )
            ],
        }
        with open(chain_path, "w", encoding="utf-8") as f:
            json.dump(chain_data, f, indent=2, ensure_ascii=False)

        print(f"\n  Audit trail exported:  {trail_path}")
        print(f"  LLM responses saved:   {llm_path}")
        print(f"  Purpose chain saved:   {chain_path}")
        print(f"  View with CLI:         python -m tools.aatp_cli view {trail_path}")

        storage.close()

    finally:
        os.unlink(db_path)


if __name__ == "__main__":
    main()
