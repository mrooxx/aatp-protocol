"""
test/test_stage3_updates.py — Tests for Stage 3 new logic (Notes 005/006)

Covers:
  1. _collect_numbers() — Recorder and Reviewer implementations
  2. INIT/TERM skip — Reviewer narrative consistency check
  3. Purpose Chain — Recorder initiation_extra, multi-session chain
  4. Agent response parsing — _parse_llm_response, _parse_root_response

All tests are local (no API calls).

Run:  python test/test_stage3_updates.py
      python -m pytest test/test_stage3_updates.py
"""

import json
import os
import sys
import tempfile
import traceback

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.canonical import canonicalize
from aatp_core.crypto import (
    generate_keypair,
    public_key_to_did_key,
    sha256_hex,
)
from aatp_core.storage import Storage
from aatp_recorder import Recorder
from aatp_recorder import _collect_numbers as recorder_collect_numbers
from aatp_reviewer import Reviewer
from aatp_reviewer import _collect_numbers as reviewer_collect_numbers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_agent_priv, _agent_pub = generate_keypair()
_agent_did = public_key_to_did_key(_agent_pub)
_principal_did = "did:example:human-principal-001"

_auditor_priv, _auditor_pub = generate_keypair()
_auditor_did = public_key_to_did_key(_auditor_pub)

_PASS = 0
_FAIL = 0


def _ok(name: str) -> None:
    global _PASS
    _PASS += 1
    print(f"  PASS: {name}")


def _fail(name: str, err: Exception) -> None:
    global _FAIL
    _FAIL += 1
    print(f"  FAIL: {name} — {err}")
    traceback.print_exc()


def _make_vc() -> dict:
    """Create a mock authorization VC."""
    return {
        "type": "AuthorizationCredential",
        "issuer": _principal_did,
        "credential_subject": {
            "agent_did": _agent_did,
            "scope": "manage household finances up to $500",
            "max_transaction_value": 500.00,
            "allowed_categories": ["utilities", "subscription", "investment"],
        },
    }


def _setup(db_path: str):
    """Create a recorder and reviewer sharing the same storage."""
    storage = Storage(db_path)
    vc = _make_vc()
    vc_hash = sha256_hex(canonicalize(vc))

    recorder = Recorder(
        agent_did=_agent_did,
        principal_did=_principal_did,
        scope_summary="manage household finances up to $500",
        private_key=_agent_priv,
        storage=storage,
        authorization_vc_hash=vc_hash,
    )

    reviewer = Reviewer(
        auditor_did=_auditor_did,
        auditor_private_key=_auditor_priv,
        storage=storage,
    )

    return recorder, reviewer, vc


def _cleanup(recorder: Recorder, db_path: str) -> None:
    try:
        recorder.storage.close()
    except Exception:
        pass
    try:
        os.unlink(db_path)
    except Exception:
        pass


# =========================================================================
# Group 1: _collect_numbers() — both Recorder and Reviewer
# =========================================================================

def test_collect_numbers_flat_dict():
    """Flat dict with numeric values."""
    data = {"amount": 127.50, "count": 3, "label": "test"}
    result = recorder_collect_numbers(data)
    assert result == {127.50, 3.0}, f"Expected {{127.5, 3.0}}, got {result}"
    # Verify Reviewer version matches
    assert reviewer_collect_numbers(data) == result
    _ok("test_collect_numbers_flat_dict")


def test_collect_numbers_nested_dict():
    """Nested dict — e.g. context field inside structured_data."""
    data = {
        "action": "pay",
        "amount": 127.50,
        "context": {
            "budget_remaining": 872.50,
            "monthly_limit": 1000.00,
        },
    }
    result = recorder_collect_numbers(data)
    assert 127.50 in result
    assert 872.50 in result
    assert 1000.00 in result
    assert len(result) == 3
    assert reviewer_collect_numbers(data) == result
    _ok("test_collect_numbers_nested_dict")


def test_collect_numbers_empty_dict():
    """Empty dict returns empty set."""
    assert recorder_collect_numbers({}) == set()
    assert reviewer_collect_numbers({}) == set()
    _ok("test_collect_numbers_empty_dict")


def test_collect_numbers_bool_excluded():
    """Booleans are not collected (isinstance(True, int) is True in Python)."""
    data = {"active": True, "deleted": False, "amount": 50.00}
    result = recorder_collect_numbers(data)
    assert result == {50.00}, f"Booleans should be excluded, got {result}"
    assert reviewer_collect_numbers(data) == result
    _ok("test_collect_numbers_bool_excluded")


def test_collect_numbers_list_of_dicts():
    """List containing dicts — e.g. line items."""
    data = {
        "items": [
            {"name": "item1", "price": 10.00},
            {"name": "item2", "price": 20.00},
        ]
    }
    result = recorder_collect_numbers(data)
    assert result == {10.00, 20.00}, f"Expected {{10.0, 20.0}}, got {result}"
    assert reviewer_collect_numbers(data) == result
    _ok("test_collect_numbers_list_of_dicts")


# =========================================================================
# Group 2: INIT/TERM skip in Reviewer
# =========================================================================

def test_init_term_skip_no_false_positive():
    """INITIATION/TERMINATION with amounts in narrative should NOT cause
    narrative_consistency failure (the skip logic from Notes 006)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        # Purpose string contains a dollar amount
        start = recorder.start_session(
            purpose="Pay electricity bill $127.50",
            mode="solo",
        )
        sid = start["session_id"]

        # Business record with matching amount in structured_data
        recorder.record_decision(
            session_id=sid,
            audit_point_type="payment_sent",
            narrative="Paid electricity bill of $127.50 to PowerCo",
            structured_data={
                "action": "pay",
                "amount": 127.50,
                "payee": "PowerCo",
                "category": "utilities",
            },
        )

        recorder.end_session(
            sid,
            outcome_summary="Paid electricity $127.50",
            total_value=127.50,
        )

        result = reviewer.check_conformance(sid, vc)

        # The key assertion: narrative_consistency should be 1.0
        # because INIT/TERM records are skipped. Only the payment_sent
        # record is checked, and its $127.50 is in structured_data.
        assert result["narrative_consistency"] == 1.0, (
            f"Expected 1.0, got {result['narrative_consistency']}. "
            f"INIT/TERM skip may not be working. "
            f"Inconsistencies: {result['inconsistencies']}"
        )

        _ok("test_init_term_skip_no_false_positive")

    finally:
        _cleanup(recorder, db_path)


def test_init_term_skip_business_still_checked():
    """Business records with mismatched amounts should still be flagged."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        start = recorder.start_session(
            purpose="Review subscriptions",
            mode="solo",
        )
        sid = start["session_id"]

        # Narrative mentions $15.99 but structured_data has $12.99
        recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Evaluating Netflix subscription at $15.99/month",
            structured_data={
                "service": "Netflix",
                "monthly_cost": 12.99,
                "category": "subscription",
                "action": "review",
            },
        )

        recorder.record_decision(
            session_id=sid,
            audit_point_type="closing",
            narrative="Completed subscription review",
            structured_data={
                "action": "close",
                "outcome": "reviewed",
                "category": "subscription",
            },
        )

        recorder.end_session(sid, outcome_summary="Reviewed", total_value=0)

        result = reviewer.check_conformance(sid, vc)

        # Business record mismatch should be caught
        assert result["narrative_consistency"] < 1.0, (
            f"Expected < 1.0 due to mismatch, got {result['narrative_consistency']}"
        )
        assert len(result["inconsistencies"]) > 0

        _ok("test_init_term_skip_business_still_checked")

    finally:
        _cleanup(recorder, db_path)


def test_init_term_skip_annotations():
    """get_session_for_review should also skip INIT/TERM in annotations."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        start = recorder.start_session(
            purpose="Pay bill $99.99",
            mode="solo",
        )
        sid = start["session_id"]

        recorder.record_decision(
            session_id=sid,
            audit_point_type="payment_sent",
            narrative="Paid $99.99 to vendor",
            structured_data={
                "action": "pay",
                "amount": 99.99,
                "category": "utilities",
            },
        )

        recorder.end_session(sid, outcome_summary="Paid $99.99", total_value=99.99)

        review_data = reviewer.get_session_for_review(sid)

        # Check INITIATION record — should have no numeric mismatch annotation
        init_record = review_data["records"][0]
        assert init_record["audit_point_type"] == "initiation"
        numeric_annotations = [
            a for a in init_record["annotations"]
            if "not found in structured_data" in a
        ]
        assert len(numeric_annotations) == 0, (
            f"INITIATION should have no numeric annotations, "
            f"got: {numeric_annotations}"
        )

        # Check TERMINATION record similarly
        term_record = review_data["records"][-1]
        assert term_record["audit_point_type"] == "termination"
        numeric_annotations_term = [
            a for a in term_record["annotations"]
            if "not found in structured_data" in a
        ]
        assert len(numeric_annotations_term) == 0, (
            f"TERMINATION should have no numeric annotations, "
            f"got: {numeric_annotations_term}"
        )

        _ok("test_init_term_skip_annotations")

    finally:
        _cleanup(recorder, db_path)


# =========================================================================
# Group 3: Purpose Chain — Recorder initiation_extra + multi-session
# =========================================================================

def test_purpose_chain_initiation_extra():
    """initiation_extra injects upstream_session_id into INITIATION record."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        # Create root session
        root = recorder.start_session(
            purpose="Manage monthly finances",
            mode="solo",
        )
        root_sid = root["session_id"]

        # Create downstream session with initiation_extra
        downstream = recorder.start_session(
            purpose="Pay electricity bill $127.50",
            mode="solo",
            initiation_extra={
                "upstream_session_id": root_sid,
                "deployer_objective": "Manage monthly finances",
            },
        )
        ds_sid = downstream["session_id"]

        # Retrieve INITIATION record of downstream session
        records = recorder.storage.get_session_records(ds_sid)
        init_record = records[0]
        sd = init_record.structured_data

        assert sd.get("upstream_session_id") == root_sid, (
            f"Expected upstream_session_id={root_sid}, got {sd.get('upstream_session_id')}"
        )
        assert sd.get("deployer_objective") == "Manage monthly finances"
        # Core fields should not be overridden
        assert sd["purpose"] == "Pay electricity bill $127.50"
        assert sd["mode"] == "solo"

        _ok("test_purpose_chain_initiation_extra")

    finally:
        _cleanup(recorder, db_path)


def test_purpose_chain_extra_does_not_override_core():
    """initiation_extra cannot override core fields (purpose, mode, audit_language)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        start = recorder.start_session(
            purpose="Real purpose",
            mode="solo",
            initiation_extra={
                "purpose": "Malicious override attempt",
                "mode": "bilateral",
                "audit_language": "zh",
                "upstream_session_id": "root-123",
            },
        )
        sid = start["session_id"]

        records = recorder.storage.get_session_records(sid)
        init_record = records[0]
        sd = init_record.structured_data

        # Core fields preserved
        assert sd["purpose"] == "Real purpose"
        assert sd["mode"] == "solo"
        assert sd["audit_language"] == "en"
        # Extra field still injected
        assert sd["upstream_session_id"] == "root-123"

        _ok("test_purpose_chain_extra_does_not_override_core")

    finally:
        _cleanup(recorder, db_path)


def test_purpose_chain_multi_session_shared_chain():
    """Multiple sessions share a single global chain with continuous sequencing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        # Root session: INIT(seq=0)
        root = recorder.start_session(
            purpose="Root session",
            mode="solo",
        )
        root_sid = root["session_id"]
        assert root["sequence_number"] == 0

        # Downstream session 1: INIT should continue from root's seq
        ds1 = recorder.start_session(
            purpose="Downstream 1",
            mode="solo",
            initiation_extra={"upstream_session_id": root_sid},
        )
        ds1_sid = ds1["session_id"]
        # Root has INIT at seq 0, so ds1 INIT should be seq 1
        assert ds1["sequence_number"] == 1, (
            f"Expected seq 1, got {ds1['sequence_number']}"
        )

        # Record a decision in ds1: seq 2
        recorder.record_decision(
            session_id=ds1_sid,
            audit_point_type="payment_sent",
            narrative="Paid $50.00",
            structured_data={
                "action": "pay",
                "amount": 50.00,
                "category": "utilities",
            },
        )

        # End ds1: TERM at seq 3
        recorder.end_session(ds1_sid, outcome_summary="Done", total_value=50.00)

        # Downstream session 2: INIT should be seq 4
        ds2 = recorder.start_session(
            purpose="Downstream 2",
            mode="solo",
            initiation_extra={"upstream_session_id": root_sid},
        )
        assert ds2["sequence_number"] == 4, (
            f"Expected seq 4, got {ds2['sequence_number']}"
        )

        # Verify chain integrity across all sessions
        l1 = reviewer.verify_chain(_agent_did, _agent_pub)
        assert l1["chain_valid"], f"Chain should be valid: {l1}"

        _ok("test_purpose_chain_multi_session_shared_chain")

    finally:
        _cleanup(recorder, db_path)


def test_purpose_chain_l1_transitions_per_session():
    """Each downstream session with full lifecycle follows valid transitions.

    Uses the complete INIT → OPENING → PAYMENT_SENT → CLOSING → TERM
    sequence required by the transition table.

    Note: The current demo trail uses a simplified lifecycle
    (INIT → business → TERM) which does NOT pass transition validation.
    This is a known issue tracked for future resolution.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        start = recorder.start_session(
            purpose="Pay electricity",
            mode="solo",
            initiation_extra={"upstream_session_id": "root-abc"},
        )
        sid = start["session_id"]

        recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Opening review of electricity bill $127.50 from PowerCo",
            structured_data={
                "action": "review",
                "amount": 127.50,
                "payee": "PowerCo",
                "category": "utilities",
            },
        )

        recorder.record_decision(
            session_id=sid,
            audit_point_type="payment_sent",
            narrative="Paid electricity bill of $127.50 to PowerCo",
            structured_data={
                "action": "pay",
                "amount": 127.50,
                "payee": "PowerCo",
                "category": "utilities",
            },
        )

        recorder.record_decision(
            session_id=sid,
            audit_point_type="closing",
            narrative="Closing electricity payment session, $127.50 paid",
            structured_data={
                "action": "close",
                "amount": 127.50,
                "outcome": "paid",
                "category": "utilities",
            },
        )

        recorder.end_session(sid, outcome_summary="Paid $127.50", total_value=127.50)

        # Get session records and verify transitions
        from aatp_reviewer import verify_transitions
        records = recorder.storage.get_session_records(sid)
        t_result = verify_transitions(records)

        assert t_result["transitions_valid"], (
            f"Transitions should be valid: {t_result['violations']}"
        )

        _ok("test_purpose_chain_l1_transitions_per_session")

    finally:
        _cleanup(recorder, db_path)


# =========================================================================
# Group 4: Agent response parsing (no API calls)
# =========================================================================

def test_parse_llm_response_valid():
    """Valid downstream decision response passes parsing."""
    from aatp_agent import _parse_llm_response

    raw = json.dumps({
        "audit_point_type": "payment_sent",
        "narrative": "Paid electricity bill of $127.50 to PowerCo.",
        "structured_data": {
            "action": "pay",
            "amount": 127.50,
            "payee": "PowerCo",
            "context": {"budget_remaining": 872.50},
        },
    })

    result = _parse_llm_response(raw)
    assert result["audit_point_type"] == "payment_sent"
    assert "127.50" in result["narrative"]
    assert result["structured_data"]["action"] == "pay"

    _ok("test_parse_llm_response_valid")


def test_parse_llm_response_invalid_type():
    """Invalid audit_point_type is rejected."""
    from aatp_agent import _parse_llm_response, LLMResponseError

    raw = json.dumps({
        "audit_point_type": "initiation",  # not allowed for downstream
        "narrative": "Starting session",
        "structured_data": {"action": "start"},
    })

    try:
        _parse_llm_response(raw)
        assert False, "Should have raised LLMResponseError"
    except LLMResponseError:
        pass

    _ok("test_parse_llm_response_invalid_type")


def test_parse_llm_response_missing_action():
    """structured_data without 'action' field is rejected."""
    from aatp_agent import _parse_llm_response, LLMResponseError

    raw = json.dumps({
        "audit_point_type": "payment_sent",
        "narrative": "Paid bill",
        "structured_data": {"amount": 50.00},  # no action field
    })

    try:
        _parse_llm_response(raw)
        assert False, "Should have raised LLMResponseError"
    except LLMResponseError:
        pass

    _ok("test_parse_llm_response_missing_action")


def test_parse_root_response_valid():
    """Valid root plan response passes parsing."""
    from aatp_agent import _parse_root_response

    raw = json.dumps({
        "plan_narrative": "Allocating budget across 3 events.",
        "allocations": [
            {"event_id": "evt_001", "purpose": "Pay electricity", "budget": 130.00},
            {"event_id": "evt_002", "purpose": "Cancel DataSync", "budget": 0},
        ],
        "budget_summary": {
            "total_budget": 1000.00,
            "allocated": 130.00,
        },
    })

    result = _parse_root_response(raw)
    assert len(result["allocations"]) == 2
    assert result["allocations"][0]["event_id"] == "evt_001"
    assert "budget" in str(result["plan_narrative"]).lower() or len(result["plan_narrative"]) > 0

    _ok("test_parse_root_response_valid")


def test_parse_root_response_missing_field():
    """Root response missing required field is rejected."""
    from aatp_agent import _parse_root_response, LLMResponseError

    raw = json.dumps({
        "plan_narrative": "Plan",
        # missing allocations and budget_summary
    })

    try:
        _parse_root_response(raw)
        assert False, "Should have raised LLMResponseError"
    except LLMResponseError:
        pass

    _ok("test_parse_root_response_missing_field")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("AATP Stage 3 Updates Tests (Notes 008)")
    print("=" * 60)

    tests = [
        # Group 1: _collect_numbers
        test_collect_numbers_flat_dict,
        test_collect_numbers_nested_dict,
        test_collect_numbers_empty_dict,
        test_collect_numbers_bool_excluded,
        test_collect_numbers_list_of_dicts,
        # Group 2: INIT/TERM skip
        test_init_term_skip_no_false_positive,
        test_init_term_skip_business_still_checked,
        test_init_term_skip_annotations,
        # Group 3: Purpose Chain
        test_purpose_chain_initiation_extra,
        test_purpose_chain_extra_does_not_override_core,
        test_purpose_chain_multi_session_shared_chain,
        test_purpose_chain_l1_transitions_per_session,
        # Group 4: Agent parsing
        test_parse_llm_response_valid,
        test_parse_llm_response_invalid_type,
        test_parse_llm_response_missing_action,
        test_parse_root_response_valid,
        test_parse_root_response_missing_field,
    ]

    for t in tests:
        try:
            t()
        except Exception as e:
            _fail(t.__name__, e)

    print("=" * 60)
    if _FAIL == 0:
        print(f"ALL {_PASS} TESTS PASSED")
    else:
        print(f"{_PASS} passed, {_FAIL} FAILED")
        sys.exit(1)
    print("=" * 60)
