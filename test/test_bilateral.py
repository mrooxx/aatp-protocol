"""
test/test_bilateral.py — Tests for transition validation and bilateral verification

Run:  python test/test_bilateral.py

Tests:
  - Transition table: valid sequences, invalid transitions, boundary constraints
  - Bilateral: cross-reference continuity, amount consistency, full pipeline
"""

import os
import sys
import tempfile
import traceback

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.crypto import generate_keypair, public_key_to_did_key
from aatp_core.record import (
    AuditPointType,
    AuditRecord,
    Authorization,
    ChainMeta,
    Counterparty,
    OperatingMode,
    RecordHeader,
)
from aatp_core.chain import seal_record
from aatp_core.storage import Storage
from aatp_core.session import AuditSession
from aatp_recorder import Recorder
from aatp_reviewer import (
    Reviewer,
    verify_transitions,
    verify_bilateral,
    VALID_TRANSITIONS,
    TRANSPARENT_TYPES,
)


# ---------------------------------------------------------------------------
# Test infrastructure
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Agent A keys
_a_priv, _a_pub = generate_keypair()
_a_did = public_key_to_did_key(_a_pub)
_a_principal = "did:example:alice"

# Agent B keys
_b_priv, _b_pub = generate_keypair()
_b_did = public_key_to_did_key(_b_pub)
_b_principal = "did:example:bob"

# Auditor keys
_aud_priv, _aud_pub = generate_keypair()
_aud_did = public_key_to_did_key(_aud_pub)


def _make_record(
    session_id: str,
    audit_point_type: AuditPointType,
    mode: OperatingMode,
    agent_did: str,
    principal_did: str,
    sequence_number: int,
    previous_hash: str = None,
    narrative: str = "test",
    structured_data: dict = None,
    counterparty: Counterparty = None,
    private_key=None,
) -> AuditRecord:
    """Create and seal a test record."""
    if structured_data is None:
        structured_data = {"action": "test"}
    if private_key is None:
        private_key = _a_priv

    record = AuditRecord(
        header=RecordHeader(
            session_id=session_id,
            audit_point_type=audit_point_type,
            mode=mode,
        ),
        narrative=narrative,
        structured_data=structured_data,
        authorization=Authorization(
            principal_did=principal_did,
            agent_did=agent_did,
            scope_summary="test scope",
        ),
        counterparty=counterparty,
        chain=ChainMeta(
            sequence_number=sequence_number,
            previous_hash=previous_hash if sequence_number > 0 else None,
        ),
    )

    sealed = seal_record(
        record=record,
        private_key=private_key,
        previous_hash=previous_hash if sequence_number > 0 else None,
    )
    return sealed


def _build_chain(
    types: list,
    mode: OperatingMode = OperatingMode.SOLO,
    agent_did: str = None,
    principal_did: str = None,
    private_key=None,
    counterparty: Counterparty = None,
    structured_data_list: list = None,
    narrative_list: list = None,
) -> list:
    """Build a chain of sealed records from a list of AuditPointTypes."""
    if agent_did is None:
        agent_did = _a_did
    if principal_did is None:
        principal_did = _a_principal
    if private_key is None:
        private_key = _a_priv

    records = []
    prev_hash = None
    session_id = "test-session-001"

    for i, apt in enumerate(types):
        sd = {"action": apt.value}
        if structured_data_list and i < len(structured_data_list):
            sd = structured_data_list[i]

        narr = f"Test record: {apt.value}"
        if narrative_list and i < len(narrative_list):
            narr = narrative_list[i]

        record = _make_record(
            session_id=session_id,
            audit_point_type=apt,
            mode=mode,
            agent_did=agent_did,
            principal_did=principal_did,
            sequence_number=i,
            previous_hash=prev_hash,
            narrative=narr,
            structured_data=sd,
            counterparty=counterparty,
            private_key=private_key,
        )
        records.append(record)
        prev_hash = record.chain.record_hash

    return records


# Shorthand
_INIT = AuditPointType.INITIATION
_TERM = AuditPointType.TERMINATION
_OPEN = AuditPointType.OPENING
_OFFR = AuditPointType.OFFER
_COFF = AuditPointType.COUNTER_OFFER
_AGRJ = AuditPointType.AGREEMENT_OR_REJECTION
_PAYS = AuditPointType.PAYMENT_SENT
_PAYC = AuditPointType.PAYMENT_CONFIRMED
_PROB = AuditPointType.PROBLEM_OR_DISPUTE
_CLOS = AuditPointType.CLOSING
_PSTS = AuditPointType.PERIODIC_STATUS
_EXTN = AuditPointType.EXTENSION


# ===================================================================
# TRANSITION TABLE TESTS
# ===================================================================

print("\n=== Transition Table Tests ===\n")


# --- Valid sequences ---

def test_valid_solo_simple():
    """Solo: INIT → OPEN → PAYMENT_SENT → CLOSING → TERM"""
    chain = _build_chain([_INIT, _OPEN, _PAYS, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    assert result["total_decision_records"] == 5
    _ok("valid_solo_simple")

try:
    test_valid_solo_simple()
except Exception as e:
    _fail("valid_solo_simple", e)


def test_valid_bilateral_negotiation():
    """Bilateral: INIT → OPEN → OFFER → COUNTER → AGREEMENT → PAY_S → PAY_C → CLOSE → TERM"""
    chain = _build_chain(
        [_INIT, _OPEN, _OFFR, _COFF, _AGRJ, _PAYS, _PAYC, _CLOS, _TERM],
        mode=OperatingMode.BILATERAL,
        counterparty=Counterparty(counterparty_did="did:example:bob"),
    )
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_bilateral_negotiation")

try:
    test_valid_bilateral_negotiation()
except Exception as e:
    _fail("valid_bilateral_negotiation", e)


def test_valid_multi_counter_offer():
    """Multiple counter-offers: INIT → OPEN → OFFER → COUNTER → COUNTER → COUNTER → AGRJ → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _COFF, _COFF, _COFF, _AGRJ, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_multi_counter_offer")

try:
    test_valid_multi_counter_offer()
except Exception as e:
    _fail("valid_multi_counter_offer", e)


def test_valid_empty_session():
    """Empty session: INIT → OPEN → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_empty_session")

try:
    test_valid_empty_session()
except Exception as e:
    _fail("valid_empty_session", e)


def test_valid_dispute_then_repay():
    """Dispute flow: ... → PAY_S → PROB → PAY_S → PAY_C → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _AGRJ, _PAYS, _PROB, _PAYS, _PAYC, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_dispute_then_repay")

try:
    test_valid_dispute_then_repay()
except Exception as e:
    _fail("valid_dispute_then_repay", e)


def test_valid_opening_direct_pay_confirmed():
    """Solo instant: INIT → OPEN → PAY_C → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _PAYC, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_opening_direct_pay_confirmed")

try:
    test_valid_opening_direct_pay_confirmed()
except Exception as e:
    _fail("valid_opening_direct_pay_confirmed", e)


def test_valid_offer_abort():
    """Abort after offer: INIT → OPEN → OFFER → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_offer_abort")

try:
    test_valid_offer_abort()
except Exception as e:
    _fail("valid_offer_abort", e)


def test_valid_counter_offer_abort():
    """Abort after counter-offer: INIT → OPEN → OFFER → COUNTER → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _COFF, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_counter_offer_abort")

try:
    test_valid_counter_offer_abort()
except Exception as e:
    _fail("valid_counter_offer_abort", e)


def test_valid_payment_sent_direct_close():
    """No confirmation: INIT → OPEN → OFFR → AGRJ → PAY_S → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _AGRJ, _PAYS, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_payment_sent_direct_close")

try:
    test_valid_payment_sent_direct_close()
except Exception as e:
    _fail("valid_payment_sent_direct_close", e)


def test_valid_agreement_then_dispute():
    """Post-agreement dispute: ... → AGRJ → PROB → AGRJ → PAY_S → ... """
    chain = _build_chain([_INIT, _OPEN, _OFFR, _AGRJ, _PROB, _AGRJ, _PAYS, _PAYC, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_agreement_then_dispute")

try:
    test_valid_agreement_then_dispute()
except Exception as e:
    _fail("valid_agreement_then_dispute", e)


def test_valid_rejection_renegotiate():
    """Rejection then renegotiate: ... → AGRJ → COFF → AGRJ → ..."""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _AGRJ, _COFF, _AGRJ, _PAYS, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_rejection_renegotiate")

try:
    test_valid_rejection_renegotiate()
except Exception as e:
    _fail("valid_rejection_renegotiate", e)


def test_valid_dispute_direct_pay_confirmed():
    """Dispute resolved with instant payment: ... → PROB → PAY_C → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _AGRJ, _PAYS, _PROB, _PAYC, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_dispute_direct_pay_confirmed")

try:
    test_valid_dispute_direct_pay_confirmed()
except Exception as e:
    _fail("valid_dispute_direct_pay_confirmed", e)


def test_valid_multi_dispute():
    """Multi-round dispute: ... → PROB → PROB → PROB → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _OFFR, _AGRJ, _PAYS, _PROB, _PROB, _PROB, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    _ok("valid_multi_dispute")

try:
    test_valid_multi_dispute()
except Exception as e:
    _fail("valid_multi_dispute", e)


# --- Transparent types ---

def test_transparent_periodic_status():
    """PERIODIC_STATUS is skipped: INIT → OPEN → [PSTS] → PAY_S → CLOSE → TERM"""
    chain = _build_chain([_INIT, _OPEN, _PSTS, _PAYS, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert result["transitions_valid"], f"Expected valid, got: {result['violations']}"
    # PERIODIC_STATUS should not be counted as decision record
    assert result["total_decision_records"] == 5  # excludes PSTS
    _ok("transparent_periodic_status")

try:
    test_transparent_periodic_status()
except Exception as e:
    _fail("transparent_periodic_status", e)


# --- Invalid sequences ---

def test_invalid_missing_initiation():
    """Chain starts with OPENING instead of INITIATION"""
    chain = _build_chain([_OPEN, _PAYS, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert not result["transitions_valid"]
    types = [v["type"] for v in result["violations"]]
    assert "MISSING_INITIATION" in types
    _ok("invalid_missing_initiation")

try:
    test_invalid_missing_initiation()
except Exception as e:
    _fail("invalid_missing_initiation", e)


def test_invalid_missing_termination():
    """Chain ends without TERMINATION"""
    chain = _build_chain([_INIT, _OPEN, _PAYS, _CLOS])
    result = verify_transitions(chain)
    assert not result["transitions_valid"]
    types = [v["type"] for v in result["violations"]]
    assert "MISSING_TERMINATION" in types
    _ok("invalid_missing_termination")

try:
    test_invalid_missing_termination()
except Exception as e:
    _fail("invalid_missing_termination", e)


def test_invalid_payment_before_opening():
    """INIT → PAY_S (skipping OPENING)"""
    chain = _build_chain([_INIT, _PAYS, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert not result["transitions_valid"]
    types = [v["type"] for v in result["violations"]]
    assert "INVALID_TRANSITION" in types
    _ok("invalid_payment_before_opening")

try:
    test_invalid_payment_before_opening()
except Exception as e:
    _fail("invalid_payment_before_opening", e)


def test_invalid_double_initiation():
    """INIT → INIT is not allowed"""
    chain = _build_chain([_INIT, _INIT, _OPEN, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert not result["transitions_valid"]
    _ok("invalid_double_initiation")

try:
    test_invalid_double_initiation()
except Exception as e:
    _fail("invalid_double_initiation", e)


def test_invalid_post_termination():
    """Record after TERMINATION"""
    chain = _build_chain([_INIT, _OPEN, _CLOS, _TERM, _OPEN])
    result = verify_transitions(chain)
    assert not result["transitions_valid"]
    types = [v["type"] for v in result["violations"]]
    assert "POST_TERMINATION_RECORD" in types
    _ok("invalid_post_termination")

try:
    test_invalid_post_termination()
except Exception as e:
    _fail("invalid_post_termination", e)


def test_invalid_pay_confirmed_to_offer():
    """PAY_C → OFFER is not allowed"""
    chain = _build_chain([_INIT, _OPEN, _PAYS, _PAYC, _OFFR, _CLOS, _TERM])
    result = verify_transitions(chain)
    assert not result["transitions_valid"]
    _ok("invalid_pay_confirmed_to_offer")

try:
    test_invalid_pay_confirmed_to_offer()
except Exception as e:
    _fail("invalid_pay_confirmed_to_offer", e)


def test_empty_chain():
    """Empty chain should be valid (vacuously true)"""
    result = verify_transitions([])
    assert result["transitions_valid"]
    assert result["total_decision_records"] == 0
    _ok("empty_chain")

try:
    test_empty_chain()
except Exception as e:
    _fail("empty_chain", e)


# ===================================================================
# BILATERAL CROSS-CHAIN TESTS
# ===================================================================

print("\n=== Bilateral Cross-Chain Tests ===\n")


def _build_bilateral_pair():
    """Build a standard bilateral negotiation: Alice buys, Bob sells.

    Alice chain: INIT → OPEN → COUNTER_OFFER → PAY_S → CLOSE → TERM
    Bob chain:   INIT → OPEN → OFFER → AGREEMENT → PAY_C → CLOSE → TERM

    Cross-references:
      Alice OPEN: no xref (first contact)
      Bob OFFER: xref Alice seq 1 (saw Alice's OPEN)
      Alice COUNTER: xref Bob seq 2 (saw Bob's OFFER)
      Bob AGREEMENT: xref Alice seq 2 (saw Alice's COUNTER)
      Alice PAY_S: xref Bob seq 3 (saw Bob's AGREEMENT)
      Bob PAY_C: xref Alice seq 3 (saw Alice's PAY_S)
      Alice CLOSE: xref Bob seq 4 (saw Bob's PAY_C)
      Bob CLOSE: xref Alice seq 4 (saw Alice's CLOSE)
    """
    cp_a = Counterparty(counterparty_did=_b_did)
    cp_b = Counterparty(counterparty_did=_a_did)

    # --- Alice chain ---
    a_types = [_INIT, _OPEN, _COFF, _PAYS, _CLOS, _TERM]
    a_counterparties = [
        Counterparty(counterparty_did=_b_did),                              # INIT
        Counterparty(counterparty_did=_b_did),                              # OPEN: no xref
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=2),     # COUNTER: saw Bob seq 2
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=3),     # PAY_S: saw Bob seq 3
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=4),     # CLOSE: saw Bob seq 4
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=5),     # TERM: saw Bob seq 5
    ]
    a_sd_list = [
        {"purpose": "buy API credits", "mode": "bilateral"},
        {"action": "opening"},
        {"action": "counter_offer", "amount": 65.0, "quantity": 10000},
        {"action": "payment_sent", "amount": 65.0, "currency": "USDC"},
        {"action": "closing", "amount": 65.0},
        {"action": "termination", "session_digest": "mock", "record_count": 6},
    ]

    alice_chain = []
    prev_hash = None
    for i, apt in enumerate(a_types):
        record = _make_record(
            session_id="bilateral-alice-001",
            audit_point_type=apt,
            mode=OperatingMode.BILATERAL,
            agent_did=_a_did,
            principal_did=_a_principal,
            sequence_number=i,
            previous_hash=prev_hash,
            narrative=f"Alice: {apt.value}",
            structured_data=a_sd_list[i],
            counterparty=a_counterparties[i],
            private_key=_a_priv,
        )
        alice_chain.append(record)
        prev_hash = record.chain.record_hash

    # --- Bob chain ---
    b_types = [_INIT, _OPEN, _OFFR, _AGRJ, _PAYC, _CLOS, _TERM]
    b_counterparties = [
        Counterparty(counterparty_did=_a_did),                              # INIT
        Counterparty(counterparty_did=_a_did),                              # OPEN
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=1),     # OFFER: saw Alice seq 1
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=2),     # AGRJ: saw Alice seq 2
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=3),     # PAY_C: saw Alice seq 3
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=4),     # CLOSE: saw Alice seq 4
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=5),     # TERM: saw Alice seq 5
    ]
    b_sd_list = [
        {"purpose": "sell API credits", "mode": "bilateral"},
        {"action": "opening"},
        {"action": "offer", "amount": 75.0, "quantity": 10000},
        {"action": "agreement", "amount": 65.0, "quantity": 10000},
        {"action": "payment_confirmed", "amount": 65.0, "currency": "USDC"},
        {"action": "closing", "amount": 65.0},
        {"action": "termination", "session_digest": "mock", "record_count": 7},
    ]

    bob_chain = []
    prev_hash = None
    for i, apt in enumerate(b_types):
        record = _make_record(
            session_id="bilateral-bob-001",
            audit_point_type=apt,
            mode=OperatingMode.BILATERAL,
            agent_did=_b_did,
            principal_did=_b_principal,
            sequence_number=i,
            previous_hash=prev_hash,
            narrative=f"Bob: {apt.value}",
            structured_data=b_sd_list[i],
            counterparty=b_counterparties[i],
            private_key=_b_priv,
        )
        bob_chain.append(record)
        prev_hash = record.chain.record_hash

    return alice_chain, bob_chain


def test_bilateral_valid():
    """Full bilateral verification — normal scenario"""
    alice, bob = _build_bilateral_pair()
    result = verify_bilateral(alice, bob, _a_pub, _b_pub)

    assert result["bilateral_valid"], f"Expected valid, got issues: {result}"
    assert result["agent_a"]["l1_integrity"]["chain_valid"]
    assert result["agent_b"]["l1_integrity"]["chain_valid"]
    assert result["agent_a"]["transitions"]["transitions_valid"]
    assert result["agent_b"]["transitions"]["transitions_valid"]
    assert result["cross_reference"]["valid"]
    assert result["cross_reference"]["references_checked"] > 0
    assert result["amount_consistency"]["valid"]
    _ok("bilateral_valid")

try:
    test_bilateral_valid()
except Exception as e:
    _fail("bilateral_valid", e)


def test_bilateral_amount_mismatch():
    """Amount mismatch: Alice says $65, Bob says $70 in agreement"""
    alice, bob = _build_bilateral_pair()

    # Tamper Bob's AGREEMENT amount (rebuild Bob chain with wrong amount)
    b_types = [_INIT, _OPEN, _OFFR, _AGRJ, _PAYC, _CLOS, _TERM]
    b_sd_list = [
        {"purpose": "sell API credits", "mode": "bilateral"},
        {"action": "opening"},
        {"action": "offer", "amount": 75.0, "quantity": 10000},
        {"action": "agreement", "amount": 70.0, "quantity": 10000},  # MISMATCH
        {"action": "payment_confirmed", "amount": 70.0, "currency": "USDC"},  # MISMATCH
        {"action": "closing", "amount": 70.0},
        {"action": "termination", "session_digest": "mock", "record_count": 7},
    ]
    b_counterparties = [
        Counterparty(counterparty_did=_a_did),
        Counterparty(counterparty_did=_a_did),
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=1),
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=2),
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=3),
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=4),
        Counterparty(counterparty_did=_a_did, counterparty_last_seq=5),
    ]

    bob_bad = []
    prev_hash = None
    for i, apt in enumerate(b_types):
        record = _make_record(
            session_id="bilateral-bob-bad",
            audit_point_type=apt,
            mode=OperatingMode.BILATERAL,
            agent_did=_b_did,
            principal_did=_b_principal,
            sequence_number=i,
            previous_hash=prev_hash,
            narrative=f"Bob: {apt.value}",
            structured_data=b_sd_list[i],
            counterparty=b_counterparties[i],
            private_key=_b_priv,
        )
        bob_bad.append(record)
        prev_hash = record.chain.record_hash

    result = verify_bilateral(alice, bob_bad, _a_pub, _b_pub)
    assert not result["amount_consistency"]["valid"]
    assert len(result["amount_consistency"]["violations"]) > 0
    _ok("bilateral_amount_mismatch")

try:
    test_bilateral_amount_mismatch()
except Exception as e:
    _fail("bilateral_amount_mismatch", e)


def test_bilateral_bad_cross_ref():
    """Cross-ref points to non-existent sequence in other chain"""
    # Build Alice chain where a cross-ref points to Bob seq 99 (doesn't exist)
    cp_bad = Counterparty(counterparty_did=_b_did, counterparty_last_seq=99)

    a_types = [_INIT, _OPEN, _COFF, _CLOS, _TERM]
    alice_bad = []
    prev_hash = None
    for i, apt in enumerate(a_types):
        cp = cp_bad if i == 2 else Counterparty(counterparty_did=_b_did)
        record = _make_record(
            session_id="bilateral-alice-bad",
            audit_point_type=apt,
            mode=OperatingMode.BILATERAL,
            agent_did=_a_did,
            principal_did=_a_principal,
            sequence_number=i,
            previous_hash=prev_hash,
            structured_data={"action": apt.value},
            counterparty=cp,
            private_key=_a_priv,
        )
        alice_bad.append(record)
        prev_hash = record.chain.record_hash

    _, bob = _build_bilateral_pair()
    result = verify_bilateral(alice_bad, bob, _a_pub, _b_pub)

    assert not result["cross_reference"]["valid"]
    violation_types = [v["type"] for v in result["cross_reference"]["violations"]]
    assert "MISSING_REFERENCE" in violation_types
    _ok("bilateral_bad_cross_ref")

try:
    test_bilateral_bad_cross_ref()
except Exception as e:
    _fail("bilateral_bad_cross_ref", e)


def test_bilateral_non_monotonic_xref():
    """Cross-references go backwards (seq 3 then seq 1)"""
    a_types = [_INIT, _OPEN, _OFFR, _COFF, _CLOS, _TERM]
    counterparties = [
        Counterparty(counterparty_did=_b_did),
        Counterparty(counterparty_did=_b_did),
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=3),  # forward ref
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=1),  # BACKWARDS
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=4),
        Counterparty(counterparty_did=_b_did, counterparty_last_seq=5),
    ]

    alice_bad = []
    prev_hash = None
    for i, apt in enumerate(a_types):
        record = _make_record(
            session_id="bilateral-alice-nonmono",
            audit_point_type=apt,
            mode=OperatingMode.BILATERAL,
            agent_did=_a_did,
            principal_did=_a_principal,
            sequence_number=i,
            previous_hash=prev_hash,
            structured_data={"action": apt.value},
            counterparty=counterparties[i],
            private_key=_a_priv,
        )
        alice_bad.append(record)
        prev_hash = record.chain.record_hash

    _, bob = _build_bilateral_pair()
    result = verify_bilateral(alice_bad, bob, _a_pub, _b_pub)

    assert not result["cross_reference"]["valid"]
    violation_types = [v["type"] for v in result["cross_reference"]["violations"]]
    assert "NON_MONOTONIC_REFERENCE" in violation_types
    _ok("bilateral_non_monotonic_xref")

try:
    test_bilateral_non_monotonic_xref()
except Exception as e:
    _fail("bilateral_non_monotonic_xref", e)


# ===================================================================
# TRANSITION TABLE COMPLETENESS CHECK
# ===================================================================

print("\n=== Transition Table Completeness ===\n")


def test_all_decision_types_covered():
    """Every non-transparent AuditPointType (except TERMINATION) has an entry in VALID_TRANSITIONS.
    TERMINATION is a terminal state with no successors, so it's not a key."""
    non_transparent = set(AuditPointType) - TRANSPARENT_TYPES - {_TERM}
    for apt in non_transparent:
        assert apt in VALID_TRANSITIONS, f"{apt.value} missing from VALID_TRANSITIONS"
    # Also verify TERMINATION is reachable (appears in at least one value set)
    reachable = set()
    for successors in VALID_TRANSITIONS.values():
        reachable |= successors
    assert _TERM in reachable, "TERMINATION must be reachable from at least one state"
    _ok("all_decision_types_covered")

try:
    test_all_decision_types_covered()
except Exception as e:
    _fail("all_decision_types_covered", e)


def test_no_self_loop_except_allowed():
    """Only COUNTER_OFFER and PROBLEM_OR_DISPUTE allow self-loops"""
    allowed_self_loop = {_COFF, _PROB}
    for apt, successors in VALID_TRANSITIONS.items():
        if apt in successors and apt not in allowed_self_loop:
            raise AssertionError(f"Unexpected self-loop: {apt.value}")
    _ok("no_self_loop_except_allowed")

try:
    test_no_self_loop_except_allowed()
except Exception as e:
    _fail("no_self_loop_except_allowed", e)


def test_termination_is_terminal():
    """TERMINATION should not appear as a key in VALID_TRANSITIONS (no successors)"""
    assert _TERM not in VALID_TRANSITIONS, "TERMINATION should have no successors"
    _ok("termination_is_terminal")

try:
    test_termination_is_terminal()
except Exception as e:
    _fail("termination_is_terminal", e)


# ===================================================================
# REVIEWER METHOD TESTS (via storage)
# ===================================================================

print("\n=== Reviewer Method Tests ===\n")


def test_reviewer_verify_session_transitions():
    """Reviewer.verify_session_transitions via storage"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        storage = Storage(db_path)

        recorder = Recorder(
            agent_did=_a_did,
            principal_did=_a_principal,
            scope_summary="test scope",
            private_key=_a_priv,
            storage=storage,
        )

        # Create a simple solo session
        session = recorder.start_session(purpose="test transitions")
        sid = session["session_id"]

        recorder.record_decision(
            session_id=sid,
            audit_point_type="opening",
            narrative="Opening test",
            structured_data={"action": "open"},
        )
        recorder.record_decision(
            session_id=sid,
            audit_point_type="payment_sent",
            narrative="Paying $50.00 for test",
            structured_data={"amount": 50.0},
        )
        recorder.record_decision(
            session_id=sid,
            audit_point_type="closing",
            narrative="Done",
            structured_data={"action": "close"},
        )
        recorder.end_session(session_id=sid, outcome_summary="completed")

        # Now verify transitions via Reviewer
        reviewer = Reviewer(
            auditor_did=_aud_did,
            auditor_private_key=_aud_priv,
            storage=storage,
        )

        result = reviewer.verify_session_transitions(sid)
        assert result["transitions_valid"], f"Violations: {result['violations']}"

        # Explicit close for Windows SQLite compatibility
        storage.close()

    _ok("reviewer_verify_session_transitions")

try:
    test_reviewer_verify_session_transitions()
except Exception as e:
    _fail("reviewer_verify_session_transitions", e)


def test_reviewer_bilateral_method():
    """Reviewer.verify_bilateral_session convenience method"""
    alice, bob = _build_bilateral_pair()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        storage = Storage(db_path)

        reviewer = Reviewer(
            auditor_did=_aud_did,
            auditor_private_key=_aud_priv,
            storage=storage,
        )

        result = reviewer.verify_bilateral_session(alice, bob, _a_pub, _b_pub)
        assert result["bilateral_valid"], f"Expected valid, got: {result}"

        # Explicit close for Windows SQLite compatibility
        storage.close()

    _ok("reviewer_bilateral_method")

try:
    test_reviewer_bilateral_method()
except Exception as e:
    _fail("reviewer_bilateral_method", e)


# ===================================================================
# Summary
# ===================================================================

print(f"\n{'='*50}")
print(f"Results: {_PASS} passed, {_FAIL} failed out of {_PASS + _FAIL}")
print(f"{'='*50}")

if _FAIL > 0:
    sys.exit(1)
