"""
test/test_reviewer.py — Tests for aatp_reviewer

Run:  python test/test_reviewer.py
"""

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
    verify_signature,
)
from aatp_core.storage import Storage
from aatp_recorder import Recorder
from aatp_reviewer import Reviewer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Agent keys
_agent_priv, _agent_pub = generate_keypair()
_agent_did = public_key_to_did_key(_agent_pub)
_principal_did = "did:example:human-principal-001"

# Auditor keys (independent from agent — Invariant 6)
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


def _make_vc(vc_hash: str = None) -> dict:
    """Create a mock authorization VC."""
    return {
        "type": "AuthorizationCredential",
        "issuer": _principal_did,
        "credential_subject": {
            "agent_did": _agent_did,
            "scope": "manage subscriptions up to $50",
            "max_transaction_value": 50.00,
            "allowed_categories": ["subscription", "streaming"],
        },
    }


def _setup(db_path: str):
    """Create a recorder and reviewer sharing the same storage."""
    storage = Storage(db_path)

    # Compute VC hash the same way reviewer will
    vc = _make_vc()
    vc_canonical = canonicalize(vc)
    vc_hash = sha256_hex(vc_canonical)

    recorder = Recorder(
        agent_did=_agent_did,
        principal_did=_principal_did,
        scope_summary="manage subscriptions up to $50",
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


def _create_sample_session(recorder: Recorder) -> str:
    """Create a complete sample session, return session_id."""
    start = recorder.start_session(
        purpose="Review monthly subscription renewals",
        mode="solo",
    )
    sid = start["session_id"]

    recorder.record_decision(
        session_id=sid,
        audit_point_type="opening",
        narrative="Evaluating Netflix subscription renewal at $15.99/month",
        structured_data={
            "service": "Netflix",
            "monthly_cost": 15.99,
            "category": "subscription",
        },
    )

    recorder.record_decision(
        session_id=sid,
        audit_point_type="agreement_or_rejection",
        narrative="Subscription renewal review: decided to keep Netflix at $15.99 monthly",
        structured_data={
            "decision": "keep",
            "monthly_cost": 15.99,
            "category": "subscription",
        },
    )

    recorder.end_session(
        sid,
        outcome_summary="Reviewed Netflix, decided to keep",
        total_value=15.99,
    )

    return sid


def _cleanup(recorder: Recorder, db_path: str) -> None:
    """Close storage and delete temp DB."""
    try:
        recorder.storage.close()
    except Exception:
        pass
    try:
        os.unlink(db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_level1_chain_verification():
    """Level 1: verify_chain returns valid for intact chain."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)

        result = reviewer.verify_chain(_agent_did, _agent_pub)
        assert result["chain_valid"], f"Chain invalid: {result}"
        assert result["total_records"] == 4  # INIT + 2 + TERM
        assert result["record_timestamp_source"] == "local_clock"
        assert result["timestamp_assurance"] == "self_reported"
        assert len(result["broken_links"]) == 0
        assert len(result["invalid_records"]) == 0

        _ok("test_level1_chain_verification")

    finally:
        _cleanup(recorder, db_path)


def test_level2_conformance_pass():
    """Level 2: conformance passes for valid session within limits."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)

        result = reviewer.check_conformance(sid, vc)
        assert result["vc_hash_match"] is True
        assert result["within_scope"] is True
        assert result["within_limits"] is True
        assert result["purpose_consistent"] is True
        assert result["narrative_consistency"] == 1.0
        assert len(result["flagged_items"]) == 0

        _ok("test_level2_conformance_pass")

    finally:
        _cleanup(recorder, db_path)


def test_level2_vc_hash_mismatch():
    """Level 2: detects VC hash mismatch."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)

        # Tamper with VC
        tampered_vc = dict(vc)
        tampered_vc["credential_subject"] = dict(vc["credential_subject"])
        tampered_vc["credential_subject"]["scope"] = "unlimited access"

        result = reviewer.check_conformance(sid, tampered_vc)
        assert result["vc_hash_match"] is False
        assert any(
            item["issue"] == "VC_HASH_MISMATCH"
            for item in result["flagged_items"]
        )

        _ok("test_level2_vc_hash_mismatch")

    finally:
        _cleanup(recorder, db_path)


def test_level2_exceeds_limit():
    """Level 2: detects spending over VC limit."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        start = recorder.start_session(
            purpose="Review expensive subscription",
            mode="solo",
        )
        sid = start["session_id"]

        # $99.99 exceeds the $50 limit in the VC
        recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Evaluating premium subscription at $99.99/month",
            structured_data={
                "service": "Premium",
                "monthly_cost": 99.99,
                "category": "subscription",
            },
        )
        recorder.end_session(sid, "Done")

        result = reviewer.check_conformance(sid, vc)
        assert result["within_limits"] is False
        assert any(
            "EXCEEDS_LIMIT" in item["issue"]
            for item in result["flagged_items"]
        )

        _ok("test_level2_exceeds_limit")

    finally:
        _cleanup(recorder, db_path)


def test_level2_out_of_scope():
    """Level 2: detects category outside allowed scope."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        start = recorder.start_session(
            purpose="Review hardware purchase",
            mode="solo",
        )
        sid = start["session_id"]

        recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Buying a keyboard for $45.00",
            structured_data={
                "item": "keyboard",
                "price": 45.00,
                "category": "hardware",  # not in allowed_categories
            },
        )
        recorder.end_session(sid, "Done")

        result = reviewer.check_conformance(sid, vc)
        assert result["within_scope"] is False
        assert any(
            "OUT_OF_SCOPE" in item["issue"]
            for item in result["flagged_items"]
        )

        _ok("test_level2_out_of_scope")

    finally:
        _cleanup(recorder, db_path)


def test_level2_purpose_drift_flagged():
    """Level 2: picks up PURPOSE_DRIFT from recorder flags."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        start = recorder.start_session(
            purpose="Review monthly subscription renewals",
            mode="solo",
        )
        sid = start["session_id"]

        # Deliberately off-topic to trigger PURPOSE_DRIFT
        recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Purchasing a new laptop from electronics retailer",
            structured_data={"item": "laptop", "price": 45.00},
        )
        recorder.end_session(sid, "Done")

        result = reviewer.check_conformance(sid, vc)
        assert result["purpose_consistent"] is False
        assert any(
            item["issue"] == "PURPOSE_DRIFT"
            for item in result["flagged_items"]
        )

        _ok("test_level2_purpose_drift_flagged")

    finally:
        _cleanup(recorder, db_path)


def test_level3_get_session_for_review():
    """Level 3 prep: formatted session data for AI review."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)

        review_data = reviewer.get_session_for_review(sid)
        assert review_data["session_id"] == sid
        assert review_data["total_records"] == 4
        assert review_data["status"] == "closed"
        assert len(review_data["records"]) == 4

        # Each record should have expected fields
        for entry in review_data["records"]:
            assert "record_id" in entry
            assert "sequence_number" in entry
            assert "audit_point_type" in entry
            assert "narrative" in entry
            assert "structured_data" in entry
            assert "annotations" in entry

        _ok("test_level3_get_session_for_review")

    finally:
        _cleanup(recorder, db_path)


def test_level3_submit_review():
    """Level 3: submit review with findings and verify signature."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)
        records = recorder.storage.get_session_records(sid)
        record_ids = [r.header.record_id for r in records]

        result = reviewer.submit_review(
            session_id=sid,
            overall_score=92,
            integrity_score=100,
            conformance_score=95,
            reasonableness_score=85,
            findings=[
                {
                    "finding": "All records properly chained and signed",
                    "severity": "info",
                    "record_refs": record_ids,
                },
                {
                    "finding": "Decision within authorized scope",
                    "severity": "info",
                    "record_refs": [record_ids[1]],
                },
            ],
            recommendations=[
                "Consider documenting alternatives considered",
            ],
        )

        assert "review_id" in result
        assert "record_hash" in result
        assert result["signature"]["signer"] == _auditor_did

        # Verify signature
        review_records = recorder.storage.get_session_reviews(sid)
        assert len(review_records) == 1
        review = review_records[0]

        # Recompute hash from stored review (exclude record_hash and signature)
        review_for_hash = {
            k: v for k, v in review.items()
            if k not in ("record_hash", "signature")
        }
        recomputed = sha256_hex(canonicalize(review_for_hash))
        assert recomputed == review["record_hash"]

        # Verify Ed25519 signature
        review_canonical = canonicalize(review_for_hash)
        assert verify_signature(
            _auditor_pub, review_canonical, review["signature"]["value"]
        )

        _ok("test_level3_submit_review")

    finally:
        _cleanup(recorder, db_path)


def test_level3_review_chain_state():
    """Level 3: review chain state updates correctly."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)
        records = recorder.storage.get_session_records(sid)
        record_ids = [r.header.record_id for r in records]

        # Submit two reviews
        r1 = reviewer.submit_review(
            session_id=sid,
            overall_score=90,
            integrity_score=100,
            conformance_score=90,
            reasonableness_score=80,
            findings=[{
                "finding": "First review",
                "severity": "info",
                "record_refs": record_ids[:1],
            }],
            recommendations=[],
        )

        r2 = reviewer.submit_review(
            session_id=sid,
            overall_score=95,
            integrity_score=100,
            conformance_score=95,
            reasonableness_score=90,
            findings=[{
                "finding": "Second review after remediation",
                "severity": "info",
                "record_refs": record_ids[:1],
            }],
            recommendations=[],
        )

        # Chain state should reflect two reviews
        state = recorder.storage.get_review_chain_state(_auditor_did)
        assert state is not None
        assert state["last_sequence_number"] == 1  # 0-indexed: 0, 1
        assert state["last_record_hash"] == r2["record_hash"]

        # Second review should link to first
        reviews = recorder.storage.get_session_reviews(sid)
        assert len(reviews) == 2

        _ok("test_level3_review_chain_state")

    finally:
        _cleanup(recorder, db_path)


def test_submit_review_validates_findings():
    """submit_review rejects findings without record_refs."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)

        try:
            reviewer.submit_review(
                session_id=sid,
                overall_score=50,
                integrity_score=50,
                conformance_score=50,
                reasonableness_score=50,
                findings=[{
                    "finding": "Missing refs",
                    "severity": "warning",
                    # No record_refs!
                }],
                recommendations=[],
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "record_refs" in str(e).lower()

        _ok("test_submit_review_validates_findings")

    finally:
        _cleanup(recorder, db_path)


def test_submit_review_validates_scores():
    """submit_review rejects invalid scores."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)
        records = recorder.storage.get_session_records(sid)

        try:
            reviewer.submit_review(
                session_id=sid,
                overall_score=150,  # invalid
                integrity_score=100,
                conformance_score=100,
                reasonableness_score=100,
                findings=[{
                    "finding": "Test",
                    "severity": "info",
                    "record_refs": [records[0].header.record_id],
                }],
                recommendations=[],
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "0-100" in str(e)

        _ok("test_submit_review_validates_scores")

    finally:
        _cleanup(recorder, db_path)


def test_full_l1_l2_l3_flow():
    """End-to-end: L1 verify → L2 conformance → L3 review."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder, reviewer, vc = _setup(db_path)
    try:
        sid = _create_sample_session(recorder)

        # L1
        l1 = reviewer.verify_chain(_agent_did, _agent_pub)
        assert l1["chain_valid"]

        # L2
        l2 = reviewer.check_conformance(sid, vc)
        assert l2["vc_hash_match"]
        assert l2["within_limits"]

        # L3 prep
        review_data = reviewer.get_session_for_review(sid)
        assert review_data["total_records"] == 4

        # L3 submit
        records = recorder.storage.get_session_records(sid)
        record_ids = [r.header.record_id for r in records]

        l3 = reviewer.submit_review(
            session_id=sid,
            overall_score=95,
            integrity_score=100,
            conformance_score=95,
            reasonableness_score=90,
            findings=[{
                "finding": "Session well-documented and within scope",
                "severity": "info",
                "record_refs": record_ids,
            }],
            recommendations=[
                "Consider adding alternatives_considered field",
            ],
        )
        assert l3["review_id"] is not None
        assert l3["signature"]["signer"] == _auditor_did

        _ok("test_full_l1_l2_l3_flow")

    finally:
        _cleanup(recorder, db_path)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("AATP Reviewer Tests")
    print("=" * 60)

    tests = [
        test_level1_chain_verification,
        test_level2_conformance_pass,
        test_level2_vc_hash_mismatch,
        test_level2_exceeds_limit,
        test_level2_out_of_scope,
        test_level2_purpose_drift_flagged,
        test_level3_get_session_for_review,
        test_level3_submit_review,
        test_level3_review_chain_state,
        test_submit_review_validates_findings,
        test_submit_review_validates_scores,
        test_full_l1_l2_l3_flow,
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
