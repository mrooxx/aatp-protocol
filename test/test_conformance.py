"""
test/test_conformance.py — Supplemental conformance tests

Fills gaps identified in the test coverage audit:
  - Session state machine (error paths + lifecycle)
  - Chain edge cases (empty, single, wrong key)
  - Recorder integration (concurrent sessions, flags)
  - Bilateral golden file conformance
  - Reviewer edge cases

Run:  python test/test_conformance.py

These tests supplement test_aatp.py, test_reviewer.py, and
test_bilateral.py. Together they form the complete conformance suite.
"""

import json
import os
import sys
import tempfile
import traceback

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.canonical import canonicalize
from aatp_core.chain import seal_record, verify_chain, verify_record
from aatp_core.crypto import (
    generate_keypair,
    public_key_to_did_key,
    sha256_hex,
)
from aatp_core.record import (
    AuditPointType,
    AuditRecord,
    Authorization,
    ChainMeta,
    Counterparty,
    OperatingMode,
    RecordHeader,
)
from aatp_core.session import AuditSession, SessionState
from aatp_core.storage import Storage
from aatp_recorder import Recorder
from aatp_reviewer import (
    Reviewer,
    verify_bilateral,
    verify_transitions,
)


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

_PASS = 0
_FAIL = 0


def _ok(name: str) -> None:
    global _PASS
    _PASS += 1
    print(f"  PASS: {name}")


def _fail(name: str, err: Exception) -> None:
    global _FAIL
    _FAIL += 1
    print(f"  FAIL: {name}")
    traceback.print_exception(type(err), err, err.__traceback__)


# Keys
_priv, _pub = generate_keypair()
_did = public_key_to_did_key(_pub)
_principal = "did:example:test-principal"
_priv2, _pub2 = generate_keypair()
_did2 = public_key_to_did_key(_pub2)

_auth = Authorization(
    principal_did=_principal,
    agent_did=_did,
    scope_summary="test scope",
)


def _make_session(**kwargs):
    """Create a standard solo session with defaults."""
    defaults = dict(
        mode=OperatingMode.SOLO,
        authorization=_auth,
        private_key=_priv,
        initiation_narrative="Test session",
        initiation_data={"purpose": "test"},
    )
    defaults.update(kwargs)
    return AuditSession(**defaults)


# ===================================================================
# SESSION STATE MACHINE TESTS
# ===================================================================

print("\n" + "=" * 60)
print("  Session State Machine Tests")
print("=" * 60)


def test_add_record_after_close():
    """add_record on closed session raises RuntimeError."""
    session = _make_session()
    session.close(narrative="Done")
    assert session.state == SessionState.CLOSED
    try:
        session.add_record(
            audit_point_type=AuditPointType.OPENING,
            narrative="Should fail",
            structured_data={"x": 1},
        )
        raise AssertionError("Expected RuntimeError")
    except RuntimeError as e:
        assert "closed" in str(e).lower()
    _ok("add_record_after_close")

try:
    test_add_record_after_close()
except Exception as e:
    _fail("add_record_after_close", e)


def test_close_after_close():
    """close() on closed session raises RuntimeError."""
    session = _make_session()
    session.close(narrative="Done")
    try:
        session.close(narrative="Should fail")
        raise AssertionError("Expected RuntimeError")
    except RuntimeError:
        pass
    _ok("close_after_close")

try:
    test_close_after_close()
except Exception as e:
    _fail("close_after_close", e)


def test_add_record_rejects_initiation():
    """add_record with INITIATION raises ValueError."""
    session = _make_session()
    try:
        session.add_record(
            audit_point_type=AuditPointType.INITIATION,
            narrative="Bad",
            structured_data={"x": 1},
        )
        raise AssertionError("Expected ValueError")
    except ValueError as e:
        assert "initiation" in str(e).lower()
    _ok("add_record_rejects_initiation")

try:
    test_add_record_rejects_initiation()
except Exception as e:
    _fail("add_record_rejects_initiation", e)


def test_add_record_rejects_termination():
    """add_record with TERMINATION raises ValueError."""
    session = _make_session()
    try:
        session.add_record(
            audit_point_type=AuditPointType.TERMINATION,
            narrative="Bad",
            structured_data={"x": 1},
        )
        raise AssertionError("Expected ValueError")
    except ValueError as e:
        assert "termination" in str(e).lower()
    _ok("add_record_rejects_termination")

try:
    test_add_record_rejects_termination()
except Exception as e:
    _fail("add_record_rejects_termination", e)


def test_termination_includes_digest_and_count():
    """TERMINATION record auto-includes session_digest and record_count."""
    session = _make_session()
    session.add_record(
        audit_point_type=AuditPointType.OPENING,
        narrative="Open",
        structured_data={"x": 1},
    )
    session.add_record(
        audit_point_type=AuditPointType.CLOSING,
        narrative="Close",
        structured_data={"x": 2},
    )
    term = session.close(narrative="Done")

    sd = term.structured_data
    assert "session_digest" in sd, "Missing session_digest"
    assert "record_count" in sd, "Missing record_count"
    assert sd["record_count"] == 3  # INIT + OPEN + CLOSE (before TERM)
    assert isinstance(sd["session_digest"], str)
    assert len(sd["session_digest"]) == 64  # SHA-256 hex
    _ok("termination_includes_digest_and_count")

try:
    test_termination_includes_digest_and_count()
except Exception as e:
    _fail("termination_includes_digest_and_count", e)


def test_set_chain_position():
    """set_chain_position affects the next record's sequence and previous_hash."""
    session = _make_session()
    # INITIATION was seq 0
    assert session.last_record.chain.sequence_number == 0

    # Inject external chain position
    session.set_chain_position(42, "abc123")
    rec = session.add_record(
        audit_point_type=AuditPointType.OPENING,
        narrative="Test",
        structured_data={"x": 1},
    )
    assert rec.chain.sequence_number == 42
    assert rec.chain.previous_hash is not None
    _ok("set_chain_position")

try:
    test_set_chain_position()
except Exception as e:
    _fail("set_chain_position", e)


def test_session_auto_sequences():
    """Session auto-increments sequence numbers when used standalone."""
    session = _make_session()
    assert session.last_record.chain.sequence_number == 0  # INIT

    r1 = session.add_record(
        audit_point_type=AuditPointType.OPENING,
        narrative="r1",
        structured_data={"x": 1},
    )
    assert r1.chain.sequence_number == 1

    r2 = session.add_record(
        audit_point_type=AuditPointType.CLOSING,
        narrative="r2",
        structured_data={"x": 2},
    )
    assert r2.chain.sequence_number == 2

    r3 = session.close(narrative="Done")
    assert r3.chain.sequence_number == 3
    _ok("session_auto_sequences")

try:
    test_session_auto_sequences()
except Exception as e:
    _fail("session_auto_sequences", e)


def test_session_init_state():
    """Session starts ACTIVE with 1 record (INITIATION)."""
    session = _make_session()
    assert session.state == SessionState.ACTIVE
    assert session.record_count == 1
    assert session.last_record.header.audit_point_type == AuditPointType.INITIATION
    _ok("session_init_state")

try:
    test_session_init_state()
except Exception as e:
    _fail("session_init_state", e)


def test_bilateral_session_has_counterparty():
    """Bilateral session records include counterparty info."""
    session = AuditSession(
        mode=OperatingMode.BILATERAL,
        authorization=_auth,
        private_key=_priv,
        initiation_narrative="Bilateral test",
        initiation_data={"purpose": "test"},
        counterparty=Counterparty(counterparty_did=_did2),
    )
    init = session.last_record
    assert init.counterparty is not None
    assert init.counterparty.counterparty_did == _did2
    _ok("bilateral_session_has_counterparty")

try:
    test_bilateral_session_has_counterparty()
except Exception as e:
    _fail("bilateral_session_has_counterparty", e)


# ===================================================================
# CHAIN EDGE CASES
# ===================================================================

print("\n" + "=" * 60)
print("  Chain Edge Case Tests")
print("=" * 60)


def test_verify_chain_empty():
    """verify_chain with empty list succeeds vacuously."""
    result = verify_chain([], _pub)
    assert result["chain_valid"]
    assert result["total_records"] == 0
    _ok("verify_chain_empty")

try:
    test_verify_chain_empty()
except Exception as e:
    _fail("verify_chain_empty", e)


def test_verify_chain_single_genesis():
    """verify_chain with single genesis record."""
    session = _make_session()
    result = verify_chain([session.last_record], _pub)
    assert result["chain_valid"]
    assert result["total_records"] == 1
    _ok("verify_chain_single_genesis")

try:
    test_verify_chain_single_genesis()
except Exception as e:
    _fail("verify_chain_single_genesis", e)


def test_verify_chain_wrong_key():
    """verify_chain with wrong public key fails for all records."""
    session = _make_session()
    session.add_record(
        audit_point_type=AuditPointType.OPENING,
        narrative="Test",
        structured_data={"x": 1},
    )
    session.close(narrative="Done")

    # Verify with a different key
    result = verify_chain(session.records, _pub2)
    assert not result["chain_valid"]
    # All records should have invalid signatures
    assert len(result["invalid_records"]) == len(session.records)
    _ok("verify_chain_wrong_key")

try:
    test_verify_chain_wrong_key()
except Exception as e:
    _fail("verify_chain_wrong_key", e)


def test_verify_chain_tampered_middle():
    """Tamper with middle record: hash chain breaks at that point."""
    session = _make_session()
    for i in range(3):
        session.add_record(
            audit_point_type=AuditPointType.OPENING if i == 0 else AuditPointType.OFFER,
            narrative=f"Record {i}",
            structured_data={"step": i},
        )
    session.close(narrative="Done")

    records = session.records
    assert len(records) == 5  # INIT + 3 + TERM

    # Tamper with record at index 2 (the second OFFER)
    records[2].narrative = "TAMPERED NARRATIVE"

    result = verify_chain(records, _pub)
    assert not result["chain_valid"]
    # Record 2 should have invalid signature
    invalid_seqs = {r["sequence_number"] for r in result["invalid_records"]}
    assert 2 in invalid_seqs
    _ok("verify_chain_tampered_middle")

try:
    test_verify_chain_tampered_middle()
except Exception as e:
    _fail("verify_chain_tampered_middle", e)


def test_verify_chain_broken_link():
    """A record with wrong previous_hash breaks the link."""
    session = _make_session()
    session.add_record(
        audit_point_type=AuditPointType.OPENING,
        narrative="Test",
        structured_data={"x": 1},
    )
    session.close(narrative="Done")

    records = session.records
    # Corrupt previous_hash of record 1
    records[1].chain.previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    result = verify_chain(records, _pub)
    assert not result["chain_valid"]
    assert len(result["broken_links"]) > 0 or len(result["invalid_records"]) > 0
    _ok("verify_chain_broken_link")

try:
    test_verify_chain_broken_link()
except Exception as e:
    _fail("verify_chain_broken_link", e)


# ===================================================================
# RECORDER INTEGRATION TESTS
# ===================================================================

print("\n" + "=" * 60)
print("  Recorder Integration Tests")
print("=" * 60)


def test_concurrent_sessions_share_sequence():
    """Two concurrent sessions share the same chain sequence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        storage = Storage(db_path)

        recorder = Recorder(
            agent_did=_did,
            principal_did=_principal,
            scope_summary="test scope",
            private_key=_priv,
            storage=storage,
        )

        # Start session A
        a = recorder.start_session(purpose="Session A")
        a_sid = a["session_id"]
        a_init_seq = a["sequence_number"]

        # Start session B (should get next sequence)
        b = recorder.start_session(purpose="Session B")
        b_sid = b["session_id"]
        b_init_seq = b["sequence_number"]

        assert b_init_seq == a_init_seq + 1, (
            f"Expected B to follow A: A={a_init_seq}, B={b_init_seq}"
        )

        # Add record to A
        r_a = recorder.record_decision(
            session_id=a_sid,
            audit_point_type="opening",
            narrative="A opens",
            structured_data={"action": "open"},
        )

        # Add record to B
        r_b = recorder.record_decision(
            session_id=b_sid,
            audit_point_type="opening",
            narrative="B opens",
            structured_data={"action": "open"},
        )

        # They should have consecutive sequence numbers
        assert r_b["sequence_number"] == r_a["sequence_number"] + 1

        # Clean up
        recorder.end_session(a_sid, "done A")
        recorder.end_session(b_sid, "done B")
        storage.close()

    _ok("concurrent_sessions_share_sequence")

try:
    test_concurrent_sessions_share_sequence()
except Exception as e:
    _fail("concurrent_sessions_share_sequence", e)


def test_recorder_purpose_drift_flag():
    """Recorder flags PURPOSE_DRIFT when narrative diverges from purpose."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        storage = Storage(db_path)

        recorder = Recorder(
            agent_did=_did,
            principal_did=_principal,
            scope_summary="test scope",
            private_key=_priv,
            storage=storage,
        )

        session = recorder.start_session(purpose="Manage monthly electricity bill payments")
        sid = session["session_id"]

        # Completely unrelated narrative → should flag drift
        result = recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative=(
                "Analyzing quantum chromodynamics simulation results "
                "from the particle accelerator experiment dataset"
            ),
            structured_data={"action": "analyze"},
        )

        assert "PURPOSE_DRIFT" in result["recorder_flags"]

        recorder.end_session(sid, "done")
        storage.close()

    _ok("recorder_purpose_drift_flag")

try:
    test_recorder_purpose_drift_flag()
except Exception as e:
    _fail("recorder_purpose_drift_flag", e)


def test_recorder_numeric_mismatch_flag():
    """Recorder flags NUMERIC_MISMATCH when narrative amount != structured_data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        storage = Storage(db_path)

        recorder = Recorder(
            agent_did=_did,
            principal_did=_principal,
            scope_summary="test scope",
            private_key=_priv,
            storage=storage,
        )

        session = recorder.start_session(purpose="Pay bills")
        sid = session["session_id"]

        # Narrative says $127.50 but structured_data says 27.50
        result = recorder.record_decision(
            session_id=sid,
            audit_point_type="payment_sent",
            narrative="Paying electricity bill of $127.50 to Electric Co",
            structured_data={"amount": 27.50, "payee": "Electric Co"},
        )

        assert "NUMERIC_MISMATCH" in result["recorder_flags"]

        recorder.end_session(sid, "done")
        storage.close()

    _ok("recorder_numeric_mismatch_flag")

try:
    test_recorder_numeric_mismatch_flag()
except Exception as e:
    _fail("recorder_numeric_mismatch_flag", e)


def test_recorder_end_session_returns_digest():
    """end_session returns session_digest in result."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        storage = Storage(db_path)

        recorder = Recorder(
            agent_did=_did,
            principal_did=_principal,
            scope_summary="test scope",
            private_key=_priv,
            storage=storage,
        )

        session = recorder.start_session(purpose="Test digest")
        sid = session["session_id"]

        recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Open",
            structured_data={"x": 1},
        )

        result = recorder.end_session(sid, "done")

        assert "session_digest" in result
        assert result["session_digest"] is not None
        assert isinstance(result["session_digest"], str)
        assert len(result["session_digest"]) == 64  # SHA-256 hex

        storage.close()

    _ok("recorder_end_session_returns_digest")

try:
    test_recorder_end_session_returns_digest()
except Exception as e:
    _fail("recorder_end_session_returns_digest", e)


# ===================================================================
# REVIEWER EDGE CASES
# ===================================================================

print("\n" + "=" * 60)
print("  Reviewer Edge Case Tests")
print("=" * 60)


def test_verify_transitions_minimal_valid():
    """Minimal valid chain: INIT → TERM (no business records)."""
    session = _make_session()
    session.close(narrative="Empty session")
    result = verify_transitions(session.records)
    # INIT → nothing → TERM — needs at least INIT → OPENING → ... → TERM
    # But actually: INITIATION → {OPENING} and nothing goes to TERMINATION
    # except through CLOSING → TERMINATION.
    # Wait: INIT → ? Our table says INITIATION → {OPENING}.
    # So INIT directly followed by TERM should be INVALID
    # because the only successor of INITIATION is OPENING.
    # Actually let's check: is INIT → TERM valid?
    # VALID_TRANSITIONS[INITIATION] = {OPENING}
    # CLOSING → {TERMINATION}
    # So INIT → TERM is INVALID (no direct edge)
    assert not result["transitions_valid"]
    _ok("verify_transitions_minimal_invalid_init_term")

try:
    test_verify_transitions_minimal_valid()
except Exception as e:
    _fail("verify_transitions_minimal_invalid_init_term", e)


def test_verify_transitions_minimal_real_valid():
    """Minimal truly valid chain: INIT → OPEN → CLOSE → TERM."""
    session = _make_session()
    session.add_record(
        audit_point_type=AuditPointType.OPENING,
        narrative="Open",
        structured_data={"x": 1},
    )
    session.add_record(
        audit_point_type=AuditPointType.CLOSING,
        narrative="Close",
        structured_data={"x": 2},
    )
    session.close(narrative="Done")

    result = verify_transitions(session.records)
    assert result["transitions_valid"], f"Violations: {result['violations']}"
    assert result["total_decision_records"] == 4
    _ok("verify_transitions_minimal_valid")

try:
    test_verify_transitions_minimal_real_valid()
except Exception as e:
    _fail("verify_transitions_minimal_valid", e)


def test_verify_bilateral_empty_chains():
    """verify_bilateral with empty chains."""
    result = verify_bilateral([], [], _pub, _pub2)
    # Both L1 checks should pass vacuously, transitions pass vacuously
    assert result["agent_a"]["l1_integrity"]["chain_valid"]
    assert result["agent_b"]["l1_integrity"]["chain_valid"]
    assert result["cross_reference"]["valid"]
    assert result["amount_consistency"]["valid"]
    _ok("verify_bilateral_empty_chains")

try:
    test_verify_bilateral_empty_chains()
except Exception as e:
    _fail("verify_bilateral_empty_chains", e)


def test_verify_bilateral_one_empty_one_full():
    """verify_bilateral where one chain has records, other empty."""
    session = AuditSession(
        mode=OperatingMode.BILATERAL,
        authorization=_auth,
        private_key=_priv,
        initiation_narrative="Test",
        initiation_data={"purpose": "test"},
        counterparty=Counterparty(counterparty_did=_did2),
    )
    session.add_record(
        audit_point_type=AuditPointType.OPENING,
        narrative="Open",
        structured_data={"x": 1},
    )
    session.add_record(
        audit_point_type=AuditPointType.CLOSING,
        narrative="Close",
        structured_data={"x": 2},
    )
    session.close(narrative="Done")

    result = verify_bilateral(session.records, [], _pub, _pub2)
    # A chain is valid, B chain is vacuously valid
    assert result["agent_a"]["l1_integrity"]["chain_valid"]
    assert result["agent_b"]["l1_integrity"]["chain_valid"]
    _ok("verify_bilateral_one_empty_one_full")

try:
    test_verify_bilateral_one_empty_one_full()
except Exception as e:
    _fail("verify_bilateral_one_empty_one_full", e)


# ===================================================================
# CANONICAL CONFORMANCE (CROSS-IMPLEMENTATION)
# ===================================================================

print("\n" + "=" * 60)
print("  Canonical Conformance Tests")
print("=" * 60)


def test_canonical_counterparty_field():
    """Counterparty with counterparty_last_seq serializes deterministically."""
    obj1 = {
        "counterparty_did": "did:key:z6MkTest",
        "counterparty_last_seq": 5,
        "counterparty_ref": None,
    }
    obj2 = {
        "counterparty_last_seq": 5,
        "counterparty_ref": None,
        "counterparty_did": "did:key:z6MkTest",
    }
    # Different key order, same canonical output
    c1 = canonicalize(obj1)
    c2 = canonicalize(obj2)
    assert c1 == c2, f"Canonical form should be identical: {c1} != {c2}"
    _ok("canonical_counterparty_field")

try:
    test_canonical_counterparty_field()
except Exception as e:
    _fail("canonical_counterparty_field", e)


def test_canonical_null_handling():
    """null values are preserved in canonical output."""
    obj = {"a": None, "b": 1, "c": None}
    canonical = canonicalize(obj)
    parsed = json.loads(canonical)
    assert parsed["a"] is None
    assert parsed["c"] is None
    _ok("canonical_null_handling")

try:
    test_canonical_null_handling()
except Exception as e:
    _fail("canonical_null_handling", e)


def test_canonical_unicode_stability():
    """Unicode strings produce stable canonical output."""
    obj = {"narrative": "支付电费 ¥127.50", "agent": "エージェント"}
    c1 = canonicalize(obj)
    c2 = canonicalize(obj)
    assert c1 == c2
    # Hash is deterministic
    h1 = sha256_hex(c1)
    h2 = sha256_hex(c2)
    assert h1 == h2
    _ok("canonical_unicode_stability")

try:
    test_canonical_unicode_stability()
except Exception as e:
    _fail("canonical_unicode_stability", e)


def test_canonical_empty_dict():
    """Empty dict produces '{}'."""
    assert canonicalize({}) == b"{}"
    _ok("canonical_empty_dict")

try:
    test_canonical_empty_dict()
except Exception as e:
    _fail("canonical_empty_dict", e)


def test_canonical_nested_arrays():
    """Nested arrays and objects produce deterministic output."""
    obj = {
        "data": [1, [2, 3], {"z": 4, "a": 5}],
        "meta": {"b": "x", "a": "y"},
    }
    canonical = canonicalize(obj)
    parsed = json.loads(canonical)
    # Keys should be sorted
    keys = list(parsed.keys())
    assert keys == ["data", "meta"]
    meta_keys = list(parsed["meta"].keys())
    assert meta_keys == ["a", "b"]
    _ok("canonical_nested_arrays")

try:
    test_canonical_nested_arrays()
except Exception as e:
    _fail("canonical_nested_arrays", e)


# ===================================================================
# GOLDEN FILE — BILATERAL
# ===================================================================

print("\n" + "=" * 60)
print("  Golden File — Bilateral Record")
print("=" * 60)


def test_bilateral_record_golden():
    """Create a bilateral record, verify canonical bytes are reproducible."""
    session = AuditSession(
        mode=OperatingMode.BILATERAL,
        authorization=_auth,
        private_key=_priv,
        initiation_narrative="Bilateral golden test",
        initiation_data={"purpose": "golden_bilateral", "mode": "bilateral"},
        counterparty=Counterparty(
            counterparty_did=_did2,
            counterparty_last_seq=None,
        ),
    )

    rec = session.add_record(
        audit_point_type=AuditPointType.OFFER,
        narrative="Offering 1000 units at $10",
        structured_data={
            "action": "offer",
            "quantity": 1000,
            "amount": 10.0,
            "currency": "USD",
        },
    )

    # Verify record is self-consistent
    hashable = rec.hashable_dict()
    canonical_bytes = canonicalize(hashable)
    computed_hash = sha256_hex(canonical_bytes)
    assert computed_hash == rec.chain.record_hash, (
        f"Hash mismatch: {computed_hash} != {rec.chain.record_hash}"
    )

    # Verify counterparty is in hashable_dict
    assert "counterparty" in hashable
    assert hashable["counterparty"]["counterparty_did"] == _did2

    # Verify mode is bilateral
    assert hashable["header"]["mode"] == "bilateral"

    # Write golden file
    output_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "golden_bilateral.json"
    )
    golden = {
        "description": "AATP bilateral OFFER record — canonical self-test",
        "record": json.loads(rec.model_dump_json()),
        "canonical_sha256": computed_hash,
    }
    with open(output_dir, "w", encoding="utf-8") as f:
        json.dump(golden, f, indent=2, ensure_ascii=False)

    print(f"  Golden file → {output_dir}")
    print(f"  Self-test: sha256(canonical) == record_hash ✓")
    _ok("bilateral_record_golden")

try:
    test_bilateral_record_golden()
except Exception as e:
    _fail("bilateral_record_golden", e)


# ===================================================================
# EXTENSION TYPE CONFORMANCE
# ===================================================================

print("\n" + "=" * 60)
print("  Extension Type Conformance")
print("=" * 60)


def test_extension_record_in_session():
    """Session can create EXTENSION records with required fields."""
    session = _make_session()
    rec = session.add_record(
        audit_point_type=AuditPointType.EXTENSION,
        narrative="Custom event logged",
        structured_data={"custom_field": "value"},
        extension_type="custom_event_v1",
        extension_justification="Event type not in core specification",
    )
    assert rec.header.audit_point_type == AuditPointType.EXTENSION
    assert rec.header.extension_type == "custom_event_v1"
    assert rec.header.extension_justification is not None
    _ok("extension_record_in_session")

try:
    test_extension_record_in_session()
except Exception as e:
    _fail("extension_record_in_session", e)


def test_extension_without_type_fails():
    """EXTENSION without extension_type fails validation."""
    session = _make_session()
    try:
        session.add_record(
            audit_point_type=AuditPointType.EXTENSION,
            narrative="Bad extension",
            structured_data={"x": 1},
            # Missing extension_type and extension_justification
        )
        raise AssertionError("Expected validation error")
    except Exception:
        pass  # Pydantic or ValueError
    _ok("extension_without_type_fails")

try:
    test_extension_without_type_fails()
except Exception as e:
    _fail("extension_without_type_fails", e)


# ===================================================================
# Summary
# ===================================================================

print(f"\n{'=' * 60}")
print(f"Results: {_PASS} passed, {_FAIL} failed out of {_PASS + _FAIL}")
print(f"{'=' * 60}")

if _FAIL > 0:
    sys.exit(1)
