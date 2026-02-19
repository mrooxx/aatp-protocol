"""
test/test_recorder.py — Tests for aatp_recorder

Run:  python test/test_recorder.py
"""

import os
import sys
import tempfile
import traceback

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.crypto import generate_keypair, public_key_to_did_key
from aatp_core.chain import verify_chain
from aatp_core.record import AuditPointType
from aatp_core.storage import Storage
from aatp_recorder import Recorder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_private_key, _public_key = generate_keypair()
_agent_did = public_key_to_did_key(_public_key)
_principal_did = "did:example:human-principal-001"

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


def _make_recorder(db_path: str) -> Recorder:
    """Create a Recorder with a fresh storage backend."""
    storage = Storage(db_path)
    return Recorder(
        agent_did=_agent_did,
        principal_did=_principal_did,
        scope_summary="Test scope: manage subscriptions up to $50",
        private_key=_private_key,
        storage=storage,
    )


def _cleanup(recorder: Recorder, db_path: str) -> None:
    """Close storage connection then delete temp DB (Windows-safe)."""
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

def test_solo_session_full_lifecycle():
    """Start -> record decisions -> end session (solo mode)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        # Start
        start = recorder.start_session(
            purpose="Review monthly subscriptions",
            mode="solo",
        )
        assert "session_id" in start
        assert "record_id" in start
        assert start["status"] == "active"
        sid = start["session_id"]

        # Record decisions
        r1 = recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Evaluating Netflix subscription at $15.99/month",
            structured_data={"service": "Netflix", "monthly_cost": 15.99},
        )
        assert "record_id" in r1
        assert r1["sequence_number"] == 1
        assert r1["recorder_flags"] == []  # no drift, amounts match

        r2 = recorder.record_decision(
            session_id=sid,
            audit_point_type="agreement_or_rejection",
            narrative="Decided to keep Netflix — within $50 budget",
            structured_data={"decision": "keep", "monthly_cost": 15.99},
        )
        assert r2["sequence_number"] == 2

        # End
        end = recorder.end_session(
            session_id=sid,
            outcome_summary="Reviewed 1 subscription, kept Netflix",
            total_value=15.99,
        )
        assert end["status"] == "closed"
        assert end["session_digest"] is not None
        assert end["total_records"] == 3  # INITIATION + 2 business

        # Verify chain from storage
        records = recorder.storage.get_session_records(sid)
        assert len(records) == 4  # INIT + 2 + TERM
        result = verify_chain(records, _public_key)
        assert result["chain_valid"], f"Chain invalid: {result}"

        _ok("test_solo_session_full_lifecycle")

    finally:
        _cleanup(recorder, db_path)


def test_bilateral_session():
    """Bilateral session with counterparty DID."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        start = recorder.start_session(
            purpose="Negotiate cloud service contract",
            mode="bilateral",
            counterparty_did="did:example:vendor-aws",
        )
        sid = start["session_id"]

        r = recorder.record_decision(
            session_id=sid,
            audit_point_type="offer",
            narrative="Negotiating cloud service contract offer at $500/month",
            structured_data={"amount": 500.00, "currency": "USD"},
        )
        assert r["recorder_flags"] == [], (
            f"Unexpected flags: {r['recorder_flags']}"
        )

        end = recorder.end_session(
            session_id=sid,
            outcome_summary="Contract negotiation completed",
            total_value=500.00,
        )
        assert end["status"] == "closed"

        _ok("test_bilateral_session")

    finally:
        _cleanup(recorder, db_path)


def test_purpose_drift_detection():
    """PURPOSE_DRIFT flag when decision diverges from session purpose."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        start = recorder.start_session(
            purpose="Review monthly subscription renewals",
            mode="solo",
        )
        sid = start["session_id"]

        # This decision is about buying a laptop — clearly off-topic
        r = recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Purchasing a new laptop from electronics retailer",
            structured_data={"item": "laptop", "price": 1299.99},
        )
        assert "PURPOSE_DRIFT" in r["recorder_flags"], (
            f"Expected PURPOSE_DRIFT, got: {r['recorder_flags']}"
        )

        # Record is still created (non-blocking)
        assert r["record_id"] is not None
        assert r["record_hash"] is not None

        recorder.end_session(sid, "Done")

        _ok("test_purpose_drift_detection")

    finally:
        _cleanup(recorder, db_path)


def test_numeric_mismatch_detection():
    """NUMERIC_MISMATCH flag when narrative amounts missing from data."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        start = recorder.start_session(
            purpose="Process payment",
            mode="solo",
        )
        sid = start["session_id"]

        # Narrative says $25.00 but structured_data has 30.00
        r = recorder.record_decision(
            session_id=sid,
            audit_point_type="payment_sent",
            narrative="Sent payment of $25.00 for service",
            structured_data={"amount": 30.00, "currency": "USD"},
        )
        assert "NUMERIC_MISMATCH" in r["recorder_flags"], (
            f"Expected NUMERIC_MISMATCH, got: {r['recorder_flags']}"
        )

        # Record still created
        assert r["record_id"] is not None

        # Flags are embedded in the sealed record
        record = recorder.storage.get_record(r["record_id"])
        assert "recorder_flags" in record.structured_data
        assert "NUMERIC_MISMATCH" in record.structured_data["recorder_flags"]

        recorder.end_session(sid, "Done")

        _ok("test_numeric_mismatch_detection")

    finally:
        _cleanup(recorder, db_path)


def test_no_false_positive_flags():
    """No flags when narrative and data are consistent."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        start = recorder.start_session(
            purpose="Review subscription costs and renewals",
            mode="solo",
        )
        sid = start["session_id"]

        r = recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Reviewing Netflix subscription renewal at $15.99",
            structured_data={"service": "Netflix", "cost": 15.99},
        )
        assert r["recorder_flags"] == [], (
            f"Unexpected flags: {r['recorder_flags']}"
        )

        # structured_data should NOT have recorder_flags key
        record = recorder.storage.get_record(r["record_id"])
        assert "recorder_flags" not in record.structured_data

        recorder.end_session(sid, "Done")

        _ok("test_no_false_positive_flags")

    finally:
        _cleanup(recorder, db_path)


def test_closed_session_rejected():
    """Cannot record to a closed session."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        start = recorder.start_session(purpose="Quick test", mode="solo")
        sid = start["session_id"]
        recorder.end_session(sid, "Done immediately")

        try:
            recorder.record_decision(
                session_id=sid,
                audit_point_type="opening",
                narrative="Should fail",
                structured_data={"fail": True},
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "not found" in str(e).lower() or "not active" in str(e).lower()

        _ok("test_closed_session_rejected")

    finally:
        _cleanup(recorder, db_path)


def test_multiple_concurrent_sessions():
    """Recorder manages multiple active sessions simultaneously."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        s1 = recorder.start_session(purpose="Session A", mode="solo")
        s2 = recorder.start_session(purpose="Session B", mode="solo")
        sid1 = s1["session_id"]
        sid2 = s2["session_id"]
        assert sid1 != sid2

        # Interleave records across sessions
        r1a = recorder.record_decision(
            sid1, "opening", "Opening A",
            structured_data={"session": "A"},
        )
        r2a = recorder.record_decision(
            sid2, "opening", "Opening B",
            structured_data={"session": "B"},
        )
        r1b = recorder.record_decision(
            sid1, "closing", "Closing A",
            structured_data={"session": "A"},
        )

        # Sequence numbers are global (agent-level), not per-session
        seqs = [
            s1["sequence_number"],   # INIT A: 0
            s2["sequence_number"],   # INIT B: 1
            r1a["sequence_number"],  # OPEN A: 2
            r2a["sequence_number"],  # OPEN B: 3
            r1b["sequence_number"],  # CLOSE A: 4
        ]
        assert seqs == sorted(seqs), f"Sequences not monotonic: {seqs}"
        assert len(set(seqs)) == len(seqs), f"Duplicate sequences: {seqs}"

        recorder.end_session(sid1, "A done")
        recorder.end_session(sid2, "B done")

        # Full agent chain should verify
        all_records = recorder.storage.get_agent_records(_agent_did)
        result = verify_chain(all_records, _public_key)
        assert result["chain_valid"], f"Chain invalid: {result}"
        assert result["total_records"] == 7  # 2 INIT + 3 biz + 2 TERM

        _ok("test_multiple_concurrent_sessions")

    finally:
        _cleanup(recorder, db_path)


def test_storage_persistence():
    """Records survive across storage reads."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        start = recorder.start_session(purpose="Persistence test", mode="solo")
        sid = start["session_id"]
        recorder.record_decision(
            sid, "opening", "Test record",
            structured_data={"persisted": True},
        )
        recorder.end_session(sid, "Done")

        # Read back from storage
        records = recorder.storage.get_session_records(sid)
        assert len(records) == 3  # INIT + OPEN + TERM

        session_meta = recorder.storage.get_session(sid)
        assert session_meta["status"] == "closed"
        assert session_meta["purpose"] == "Persistence test"

        chain_state = recorder.storage.get_chain_state(_agent_did)
        assert chain_state["total_records"] == 3

        _ok("test_storage_persistence")

    finally:
        _cleanup(recorder, db_path)


def test_extension_record_via_recorder():
    """EXTENSION records through recorder."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    recorder = _make_recorder(db_path)
    try:
        start = recorder.start_session(purpose="Extension test", mode="solo")
        sid = start["session_id"]

        r = recorder.record_decision(
            session_id=sid,
            audit_point_type="extension",
            narrative="Custom compliance check",
            structured_data={"check": "AML", "result": "pass"},
            extension_type="compliance_check",
            extension_justification="AML not covered by core 8 types",
        )
        assert r["record_id"] is not None

        record = recorder.storage.get_record(r["record_id"])
        assert record.header.extension_type == "compliance_check"

        recorder.end_session(sid, "Done")

        _ok("test_extension_record_via_recorder")

    finally:
        _cleanup(recorder, db_path)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("AATP Recorder Tests")
    print("=" * 60)

    tests = [
        test_solo_session_full_lifecycle,
        test_bilateral_session,
        test_purpose_drift_detection,
        test_numeric_mismatch_detection,
        test_no_false_positive_flags,
        test_closed_session_rejected,
        test_multiple_concurrent_sessions,
        test_storage_persistence,
        test_extension_record_via_recorder,
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
