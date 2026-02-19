"""
test/test_session.py — Tests for aatp_core.session

Run:  python test/test_session.py
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.crypto import generate_keypair, public_key_to_did_key
from aatp_core.chain import verify_chain, verify_record
from aatp_core.record import (
    AuditPointType,
    Authorization,
    Counterparty,
    OperatingMode,
)
from aatp_core.session import AuditSession, SessionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_private_key, _public_key = generate_keypair()
_agent_did = public_key_to_did_key(_public_key)
_principal_did = "did:example:human-principal-001"

_PASS = 0
_FAIL = 0


def _auth() -> Authorization:
    return Authorization(
        principal_did=_principal_did,
        agent_did=_agent_did,
        scope_summary="Test scope: manage subscriptions up to $50",
    )


def _ok(name: str) -> None:
    global _PASS
    _PASS += 1
    print(f"  PASS: {name}")


def _fail(name: str, err: Exception) -> None:
    global _FAIL
    _FAIL += 1
    print(f"  FAIL: {name} — {err}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_solo_session_lifecycle():
    """Basic solo session: init → add records → close."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Starting subscription review",
        initiation_data={"trigger": "scheduled", "budget_limit": 50.00},
    )

    # After init: ACTIVE, 1 record (INITIATION)
    assert session.state == SessionState.ACTIVE
    assert session.record_count == 1
    assert session.records[0].header.audit_point_type == AuditPointType.INITIATION
    assert session.records[0].chain.sequence_number == session.next_sequence - 1

    # Add business records
    r1 = session.add_record(
        AuditPointType.OPENING,
        narrative="Evaluating Netflix subscription renewal",
        structured_data={"service": "Netflix", "monthly_cost": 15.99},
    )
    assert r1.header.audit_point_type == AuditPointType.OPENING
    assert r1.chain.sequence_number == 1
    assert session.record_count == 2

    r2 = session.add_record(
        AuditPointType.AGREEMENT_OR_REJECTION,
        narrative="Decided to keep Netflix — within budget",
        structured_data={"decision": "keep", "reason": "within_budget"},
    )
    assert r2.chain.sequence_number == 2
    assert session.record_count == 3

    # Close
    term = session.close(
        narrative="Subscription review completed",
        structured_data={"outcome": "1 subscription reviewed"},
    )
    assert term.header.audit_point_type == AuditPointType.TERMINATION
    assert session.state == SessionState.CLOSED
    assert session.record_count == 4
    assert "session_digest" in term.structured_data
    assert term.structured_data["record_count"] == 3  # excludes TERMINATION itself

    _ok("test_solo_session_lifecycle")


def test_chain_integrity():
    """All records in a session form a valid chain."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Chain integrity test",
        initiation_data={"test": True},
    )

    session.add_record(
        AuditPointType.OPENING,
        narrative="Open",
        structured_data={"step": 1},
    )
    session.add_record(
        AuditPointType.OFFER,
        narrative="Offer",
        structured_data={"step": 2},
    )
    session.close(
        narrative="Done",
    )

    result = verify_chain(session.records, _public_key)
    assert result["chain_valid"], f"Chain invalid: {result}"
    assert result["total_records"] == 4

    _ok("test_chain_integrity")


def test_bilateral_session():
    """Bilateral session requires counterparty with DID."""
    cp = Counterparty(
        counterparty_did="did:example:vendor-xyz",
        counterparty_ref="vendor-xyz@example.com",
    )

    session = AuditSession(
        mode=OperatingMode.BILATERAL,
        authorization=_auth(),
        private_key=_private_key,
        counterparty=cp,
        initiation_narrative="Bilateral negotiation started",
        initiation_data={"counterparty": "vendor-xyz"},
    )

    assert session.state == SessionState.ACTIVE
    assert session.records[0].counterparty is not None
    assert session.records[0].counterparty.counterparty_did == "did:example:vendor-xyz"

    r = session.add_record(
        AuditPointType.OFFER,
        narrative="Proposed $100 for service",
        structured_data={"amount": 100, "currency": "USD"},
    )
    assert r.counterparty.counterparty_did == "did:example:vendor-xyz"

    session.close(narrative="Negotiation ended")

    result = verify_chain(session.records, _public_key)
    assert result["chain_valid"]

    _ok("test_bilateral_session")


def test_unilateral_session():
    """Unilateral session: counterparty optional."""
    # With counterparty (ref only, no DID)
    cp = Counterparty(counterparty_ref="amazon.com")
    session = AuditSession(
        mode=OperatingMode.UNILATERAL,
        authorization=_auth(),
        private_key=_private_key,
        counterparty=cp,
        initiation_narrative="Unilateral purchase tracking",
        initiation_data={"vendor": "amazon.com"},
    )
    session.add_record(
        AuditPointType.PAYMENT_SENT,
        narrative="Payment sent",
        structured_data={"amount": 29.99},
    )
    session.close(narrative="Done")
    assert session.record_count == 3

    # Without counterparty
    session2 = AuditSession(
        mode=OperatingMode.UNILATERAL,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="No counterparty test",
        initiation_data={"test": True},
    )
    session2.close(narrative="Immediate close")
    assert session2.record_count == 2

    _ok("test_unilateral_session")


def test_extension_record():
    """EXTENSION records require type and justification."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Extension test",
        initiation_data={"test": True},
    )

    r = session.add_record(
        AuditPointType.EXTENSION,
        narrative="Custom compliance check performed",
        structured_data={"check": "AML", "result": "pass"},
        extension_type="compliance_check",
        extension_justification="AML checks not covered by core 8 types",
    )
    assert r.header.extension_type == "compliance_check"
    assert r.header.extension_justification is not None

    session.close(narrative="Done")

    _ok("test_extension_record")


def test_closed_session_rejects_records():
    """Cannot add records after close."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Short session",
        initiation_data={"test": True},
    )
    session.close(narrative="Closing immediately")

    try:
        session.add_record(
            AuditPointType.OPENING,
            narrative="Should fail",
            structured_data={"fail": True},
        )
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "closed" in str(e).lower()

    # close() again should also fail
    try:
        session.close(narrative="Double close")
        assert False, "Should have raised RuntimeError"
    except RuntimeError:
        pass

    _ok("test_closed_session_rejects_records")


def test_lifecycle_types_rejected_in_add_record():
    """add_record() rejects INITIATION and TERMINATION."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Guard test",
        initiation_data={"test": True},
    )

    for apt in (AuditPointType.INITIATION, AuditPointType.TERMINATION):
        try:
            session.add_record(
                apt,
                narrative="Should be rejected",
                structured_data={"fail": True},
            )
            assert False, f"{apt.value} should have been rejected"
        except ValueError as e:
            assert "managed by the session" in str(e).lower() or apt.value in str(e).lower()

    session.close(narrative="Done")

    _ok("test_lifecycle_types_rejected_in_add_record")


def test_session_id_consistency():
    """All records in a session share the same session_id."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Session ID test",
        initiation_data={"test": True},
    )
    session.add_record(
        AuditPointType.OPENING,
        narrative="Record 1",
        structured_data={"n": 1},
    )
    session.close(narrative="Done")

    sid = session.session_id
    for r in session.records:
        assert r.header.session_id == sid, (
            f"Record {r.header.record_id} has session_id "
            f"{r.header.session_id}, expected {sid}"
        )

    _ok("test_session_id_consistency")


def test_sequence_continuity():
    """Sequence numbers are continuous starting from sequence_start."""
    # Default: start at 0
    s1 = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Seq test",
        initiation_data={"test": True},
    )
    s1.add_record(AuditPointType.OPENING, "Open", {"n": 1})
    s1.close(narrative="Done")

    for i, r in enumerate(s1.records):
        assert r.chain.sequence_number == i, (
            f"Expected seq {i}, got {r.chain.sequence_number}"
        )

    # Cross-session continuity: start at 4
    s2 = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Continued session",
        initiation_data={"continued": True},
        previous_hash=s1.previous_hash,
        sequence_start=s1.next_sequence,
    )
    s2.add_record(AuditPointType.OPENING, "Open", {"n": 1})
    s2.close(narrative="Done")

    expected_start = s1.next_sequence
    for i, r in enumerate(s2.records):
        assert r.chain.sequence_number == expected_start + i

    # The first record of s2 should link to the last record of s1
    assert s2.records[0].chain.previous_hash == s1.previous_hash

    _ok("test_sequence_continuity")


def test_cross_session_chain_verification():
    """Two sessions form a valid chain when linked."""
    s1 = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Session 1",
        initiation_data={"session": 1},
    )
    s1.add_record(AuditPointType.OPENING, "Open", {"n": 1})
    s1.close(narrative="Done session 1")

    s2 = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Session 2",
        initiation_data={"session": 2},
        previous_hash=s1.previous_hash,
        sequence_start=s1.next_sequence,
    )
    s2.add_record(AuditPointType.OPENING, "Open", {"n": 2})
    s2.close(narrative="Done session 2")

    # Combined chain should verify
    all_records = s1.records + s2.records
    result = verify_chain(all_records, _public_key)
    assert result["chain_valid"], f"Cross-session chain invalid: {result}"
    assert result["total_records"] == 6  # 3 + 3

    _ok("test_cross_session_chain_verification")


def test_periodic_status_record():
    """PERIODIC_STATUS records work as supplementary type."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Long-running session",
        initiation_data={"expected_duration": "1h"},
    )
    r = session.add_record(
        AuditPointType.PERIODIC_STATUS,
        narrative="Still processing; 50% complete",
        structured_data={"progress": 0.5, "elapsed_minutes": 30},
    )
    assert r.header.audit_point_type == AuditPointType.PERIODIC_STATUS
    session.close(narrative="Done")

    _ok("test_periodic_status_record")


def test_individual_record_verification():
    """Each record individually verifies."""
    session = AuditSession(
        mode=OperatingMode.SOLO,
        authorization=_auth(),
        private_key=_private_key,
        initiation_narrative="Verify each",
        initiation_data={"test": True},
    )
    session.add_record(AuditPointType.OPENING, "Open", {"n": 1})
    session.add_record(AuditPointType.CLOSING, "Close biz", {"n": 2})
    session.close(narrative="Done")

    for r in session.records:
        v = verify_record(r, _public_key)
        assert v["hash_valid"], f"Hash invalid for seq {r.chain.sequence_number}"
        assert v["signature_valid"], f"Sig invalid for seq {r.chain.sequence_number}"
        assert v["signer_match"], f"Signer mismatch for seq {r.chain.sequence_number}"

    _ok("test_individual_record_verification")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("AATP Session Tests")
    print("=" * 60)

    tests = [
        test_solo_session_lifecycle,
        test_chain_integrity,
        test_bilateral_session,
        test_unilateral_session,
        test_extension_record,
        test_closed_session_rejects_records,
        test_lifecycle_types_rejected_in_add_record,
        test_session_id_consistency,
        test_sequence_continuity,
        test_cross_session_chain_verification,
        test_periodic_status_record,
        test_individual_record_verification,
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
