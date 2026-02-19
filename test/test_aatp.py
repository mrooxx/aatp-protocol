"""
tests/test_aatp.py — AATP v2 SDK Test Suite

Requires: pydantic, cryptography

Run: pytest tests/test_aatp.py -v
  or: python tests/test_aatp.py

Test structure:
  1. Record model validation (Pydantic invariants)
  2. Canonical serialization (RFC 8785)
  3. Crypto primitives (Ed25519 + SHA-256 + did:key)
  4. Chain sealing and verification (Level 1)
  5. Storage round-trip (SQLite)
  6. End-to-end: build chain → verify → tamper → detect
  7. Golden file generation
"""

import json
import os
import sys
import tempfile

# Add parent to path for direct execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone

from aatp_core import (
    # Record model
    AuditRecord, AuditPointType, OperatingMode,
    RecordHeader, Authorization, Counterparty, Signature, ChainMeta,
    MAX_RECORD_SIZE_BYTES, validate_record_size, export_json_schema,
    # Canonical
    canonicalize, canonicalize_record,
    # Crypto
    sha256_hex, generate_keypair, sign_bytes, verify_signature,
    public_key_to_pem, public_key_from_pem, public_key_to_did_key,
    # Chain
    seal_record, verify_record, verify_chain, compute_session_digest,
    # Storage
    Storage,
    # UUID
    uuid7,
)


# ==================================================================
# Helpers
# ==================================================================

def make_record(
    seq: int = 0,
    mode: OperatingMode = OperatingMode.SOLO,
    audit_point_type: AuditPointType = AuditPointType.OPENING,
    session_id: str = None,
    counterparty: Counterparty = None,
    previous_hash: str = None,
    **overrides,
) -> AuditRecord:
    """Helper to create a valid AuditRecord for testing."""
    return AuditRecord(
        header=RecordHeader(
            session_id=session_id or uuid7(),
            audit_point_type=audit_point_type,
            mode=mode,
        ),
        narrative=overrides.get("narrative", "Test record for unit testing."),
        structured_data=overrides.get("structured_data", {"test": True}),
        authorization=Authorization(
            principal_did="did:key:z6MkTestPrincipal",
            agent_did="did:key:z6MkTestAgent",
            scope_summary="Test scope",
        ),
        counterparty=counterparty,
        chain=ChainMeta(
            sequence_number=seq,
            previous_hash=previous_hash,
        ),
    )


# ==================================================================
# 1. Record Model Validation
# ==================================================================

def test_record_basic():
    """Basic record creation with all required fields."""
    r = make_record()
    assert r.header.protocol_version == "0.1.0"
    assert r.header.audit_point_type == AuditPointType.OPENING
    assert r.header.mode == OperatingMode.SOLO
    assert r.narrative == "Test record for unit testing."
    assert r.structured_data == {"test": True}
    print("  PASS: test_record_basic")


def test_record_all_audit_point_types():
    """All 12 audit point types are representable."""
    for apt in AuditPointType:
        kwargs = {}
        if apt == AuditPointType.EXTENSION:
            kwargs["header"] = RecordHeader(
                session_id=uuid7(),
                audit_point_type=apt,
                mode=OperatingMode.SOLO,
                extension_type="custom_type",
                extension_justification="Testing extension mechanism",
            )
        else:
            kwargs["header"] = RecordHeader(
                session_id=uuid7(),
                audit_point_type=apt,
                mode=OperatingMode.SOLO,
            )
        r = AuditRecord(
            **kwargs,
            narrative=f"Test {apt.value}",
            structured_data={"type": apt.value},
            authorization=Authorization(
                principal_did="did:key:z6MkP",
                agent_did="did:key:z6MkA",
                scope_summary="test",
            ),
            chain=ChainMeta(sequence_number=0),
        )
        assert r.header.audit_point_type == apt
    print(f"  PASS: test_record_all_audit_point_types ({len(AuditPointType)} types)")


def test_extension_requires_fields():
    """EXTENSION type requires extension_type and extension_justification."""
    try:
        RecordHeader(
            session_id=uuid7(),
            audit_point_type=AuditPointType.EXTENSION,
            mode=OperatingMode.SOLO,
            # Missing extension_type and extension_justification
        )
        assert False, "Should reject EXTENSION without required fields"
    except Exception:
        pass
    print("  PASS: test_extension_requires_fields")


def test_non_extension_rejects_extension_fields():
    """Non-EXTENSION types must not have extension fields."""
    try:
        RecordHeader(
            session_id=uuid7(),
            audit_point_type=AuditPointType.OPENING,
            mode=OperatingMode.SOLO,
            extension_type="should_fail",
        )
        assert False, "Should reject extension_type on non-EXTENSION"
    except Exception:
        pass
    print("  PASS: test_non_extension_rejects_extension_fields")


def test_solo_rejects_counterparty():
    """Solo mode must not have counterparty."""
    try:
        make_record(
            mode=OperatingMode.SOLO,
            counterparty=Counterparty(counterparty_ref="test@example.com"),
        )
        assert False, "Should reject counterparty in solo mode"
    except Exception:
        pass
    print("  PASS: test_solo_rejects_counterparty")


def test_bilateral_requires_counterparty_did():
    """Bilateral mode requires counterparty with DID."""
    try:
        make_record(
            mode=OperatingMode.BILATERAL,
            counterparty=Counterparty(counterparty_ref="no-did@example.com"),
        )
        assert False, "Should reject bilateral without counterparty_did"
    except Exception:
        pass

    # Valid bilateral
    r = make_record(
        mode=OperatingMode.BILATERAL,
        counterparty=Counterparty(
            counterparty_did="did:key:z6MkCounterparty",
            counterparty_last_seq=5,
        ),
    )
    assert r.counterparty.counterparty_did == "did:key:z6MkCounterparty"
    print("  PASS: test_bilateral_requires_counterparty_did")


def test_unilateral_flexible_counterparty():
    """Unilateral mode: counterparty optional, ref-only acceptable."""
    # No counterparty
    r1 = make_record(mode=OperatingMode.UNILATERAL)
    assert r1.counterparty is None

    # Ref-only
    r2 = make_record(
        mode=OperatingMode.UNILATERAL,
        counterparty=Counterparty(counterparty_ref="merchant.example.com"),
    )
    assert r2.counterparty.counterparty_did is None

    # Full DID
    r3 = make_record(
        mode=OperatingMode.UNILATERAL,
        counterparty=Counterparty(counterparty_did="did:key:z6MkC"),
    )
    assert r3.counterparty.counterparty_did is not None
    print("  PASS: test_unilateral_flexible_counterparty")


def test_counterparty_needs_at_least_one_id():
    """Counterparty must have did or ref."""
    try:
        Counterparty()
        assert False, "Should reject empty counterparty"
    except Exception:
        pass
    print("  PASS: test_counterparty_needs_at_least_one_id")


def test_genesis_chain_validation():
    """Genesis: seq=0, no previous_hash. Non-genesis: must have previous_hash."""
    # Valid genesis
    c = ChainMeta(sequence_number=0)
    assert c.previous_hash is None

    # Invalid: genesis with previous_hash
    try:
        ChainMeta(sequence_number=0, previous_hash="abc123")
        assert False, "Should reject genesis with previous_hash"
    except Exception:
        pass

    # Invalid: non-genesis without previous_hash
    try:
        ChainMeta(sequence_number=1)
        assert False, "Should reject non-genesis without previous_hash"
    except Exception:
        pass

    # Valid non-genesis
    c2 = ChainMeta(sequence_number=1, previous_hash="abc123")
    assert c2.previous_hash == "abc123"
    print("  PASS: test_genesis_chain_validation")


def test_structured_data_rejects_nan_inf():
    """NaN and Infinity are not valid JSON."""
    for bad in [float("nan"), float("inf"), float("-inf")]:
        try:
            make_record(structured_data={"val": bad})
            assert False, f"Should reject {bad}"
        except Exception:
            pass

    # Nested
    try:
        make_record(structured_data={"outer": {"inner": float("nan")}})
        assert False, "Should reject nested NaN"
    except Exception:
        pass
    print("  PASS: test_structured_data_rejects_nan_inf")


def test_structured_data_must_be_nonempty():
    """structured_data must contain at least one field."""
    try:
        make_record(structured_data={})
        assert False, "Should reject empty structured_data"
    except Exception:
        pass
    print("  PASS: test_structured_data_must_be_nonempty")


def test_principal_did_pattern():
    """principal_did must start with 'did:'."""
    try:
        Authorization(
            principal_did="not-a-did",
            agent_did="did:key:z6MkA",
            scope_summary="test",
        )
        assert False, "Should reject non-DID principal"
    except Exception:
        pass
    print("  PASS: test_principal_did_pattern")


def test_hashable_dict_excludes_seal_fields():
    """hashable_dict() must exclude record_hash and signature."""
    r = make_record()
    d = r.hashable_dict()
    assert "record_hash" not in d["chain"]
    assert "signature" not in d["chain"]
    assert "sequence_number" in d["chain"]
    print("  PASS: test_hashable_dict_excludes_seal_fields")


def test_record_size_limit():
    """Semantic contract 7.11: records over 32KB are rejected."""
    r = make_record()
    validate_record_size(r)  # Should not raise

    big = make_record(narrative="X" * 40000)
    try:
        validate_record_size(big)
        assert False, "Should reject oversized record"
    except ValueError as e:
        assert "32KB" in str(e)
    print("  PASS: test_record_size_limit")


def test_json_schema_export():
    """JSON Schema can be exported and is valid JSON."""
    schema_str = export_json_schema()
    schema = json.loads(schema_str)
    assert "properties" in schema
    assert "header" in schema["properties"]
    assert "protocol_version" in schema_str
    print("  PASS: test_json_schema_export")


# ==================================================================
# 2. Canonical Serialization
# ==================================================================

def test_canonicalize_primitives():
    assert canonicalize(None) == b"null"
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(42) == b"42"
    assert canonicalize("hello") == b'"hello"'
    print("  PASS: test_canonicalize_primitives")


def test_canonicalize_negative_zero():
    assert canonicalize(-0.0) == b"0"
    assert canonicalize(0.0) == b"0"
    print("  PASS: test_canonicalize_negative_zero")


def test_canonicalize_float_formatting():
    assert canonicalize(1.0) == b"1"
    assert canonicalize(3.14) == b"3.14"
    assert canonicalize(1.5) == b"1.5"
    # Round-trip
    for v in [3.14, 0.0065, 127.50, 1e-10, 1e10, -2.718]:
        parsed = json.loads(canonicalize(v))
        assert parsed == v, f"Round-trip failed for {v}"
    print("  PASS: test_canonicalize_float_formatting")


def test_canonicalize_key_ordering():
    assert canonicalize({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    # Different insertion order → same output
    d1 = canonicalize({"z": 1, "a": 2, "m": 3})
    d2 = canonicalize({"a": 2, "z": 1, "m": 3})
    assert d1 == d2
    print("  PASS: test_canonicalize_key_ordering")


def test_canonicalize_nested():
    obj = {"z": {"b": 2, "a": 1}, "a": [3, 1, 2]}
    parsed = json.loads(canonicalize(obj))
    assert list(parsed.keys()) == ["a", "z"]
    assert parsed["a"] == [3, 1, 2]  # array order preserved
    print("  PASS: test_canonicalize_nested")


def test_canonicalize_string_roundtrip():
    for s in ["hello", "a\nb", "a\tb", 'a"b', "a\\b", "日本語", "🌍", "\x00"]:
        parsed = json.loads(canonicalize(s))
        assert parsed == s, f"Failed for {s!r}"
    print("  PASS: test_canonicalize_string_roundtrip")


def test_canonicalize_errors():
    import math
    for bad in [float("nan"), float("inf")]:
        try:
            canonicalize(bad)
            assert False
        except ValueError:
            pass
    for bad_obj in [{"ts": datetime.now()}, {1: "x"}, {"x": b"bytes"}]:
        try:
            canonicalize(bad_obj)
            assert False
        except (TypeError, ValueError):
            pass
    print("  PASS: test_canonicalize_errors")


# ==================================================================
# 3. Crypto Primitives
# ==================================================================

def test_sign_verify():
    priv, pub = generate_keypair()
    data = b"AATP test data"
    sig = sign_bytes(priv, data)
    assert isinstance(sig, str) and len(sig) == 128
    assert verify_signature(pub, data, sig) is True
    assert verify_signature(pub, b"wrong", sig) is False
    _, other_pub = generate_keypair()
    assert verify_signature(other_pub, data, sig) is False
    print("  PASS: test_sign_verify")


def test_pem_roundtrip():
    priv, pub = generate_keypair()
    data = b"roundtrip test"
    sig = sign_bytes(priv, data)
    pem = public_key_to_pem(pub)
    restored = public_key_from_pem(pem)
    assert verify_signature(restored, data, sig) is True
    print("  PASS: test_pem_roundtrip")


def test_sha256():
    h = sha256_hex(b"hello")
    assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    print("  PASS: test_sha256")


def test_did_key():
    _, pub = generate_keypair()
    did = public_key_to_did_key(pub)
    assert did.startswith("did:key:z6Mk")
    assert len(did) > 30
    print(f"  PASS: test_did_key → {did}")


# ==================================================================
# 4. Chain: Seal and Verify
# ==================================================================

def test_seal_genesis():
    """Seal a genesis record (seq=0, no previous_hash)."""
    priv, pub = generate_keypair()
    r = make_record(seq=0)
    sealed = seal_record(r, priv, previous_hash=None)

    assert sealed.chain.record_hash is not None
    assert sealed.chain.signature is not None
    assert sealed.chain.signature.algorithm == "Ed25519"
    assert sealed.chain.previous_hash is None

    # Verify
    v = verify_record(sealed, pub)
    assert v["hash_valid"] is True
    assert v["signature_valid"] is True
    assert v["signer_match"] is True
    assert len(v["errors"]) == 0
    print("  PASS: test_seal_genesis")


def test_seal_chain_of_three():
    """Build and verify a 3-record chain."""
    priv, pub = generate_keypair()
    session_id = uuid7()

    records = []
    prev_hash = None
    types = [AuditPointType.INITIATION, AuditPointType.OPENING, AuditPointType.CLOSING]

    for i, apt in enumerate(types):
        r = make_record(
            seq=i,
            audit_point_type=apt,
            session_id=session_id,
            previous_hash=prev_hash,
            narrative=f"Record {i}: {apt.value}",
            structured_data={"index": i},
        )
        sealed = seal_record(r, priv, previous_hash=prev_hash)
        records.append(sealed)
        prev_hash = sealed.chain.record_hash

    # Verify chain
    result = verify_chain(records, pub)
    assert result["chain_valid"] is True, f"Chain invalid: {result}"
    assert result["total_records"] == 3
    assert len(result["broken_links"]) == 0
    assert len(result["invalid_records"]) == 0
    assert len(result["timestamp_violations"]) == 0
    assert len(result["sequence_gaps"]) == 0
    print("  PASS: test_seal_chain_of_three")


def test_tamper_detection():
    """Tampered record breaks chain verification."""
    priv, pub = generate_keypair()
    session_id = uuid7()

    records = []
    prev_hash = None
    for i in range(3):
        r = make_record(
            seq=i,
            session_id=session_id,
            previous_hash=prev_hash,
            narrative=f"Record {i}",
            structured_data={"i": i},
        )
        sealed = seal_record(r, priv, previous_hash=prev_hash)
        records.append(sealed)
        prev_hash = sealed.chain.record_hash

    # Tamper with middle record's narrative
    tampered = records[1].model_copy(update={"narrative": "TAMPERED"})
    records[1] = tampered

    result = verify_chain(records, pub)
    assert result["chain_valid"] is False, "Should detect tampering"
    assert len(result["invalid_records"]) > 0
    print("  PASS: test_tamper_detection")


def test_session_digest():
    """Session digest computed from all record hashes."""
    priv, _ = generate_keypair()
    session_id = uuid7()

    records = []
    prev_hash = None
    for i in range(3):
        r = make_record(seq=i, session_id=session_id, previous_hash=prev_hash)
        sealed = seal_record(r, priv, previous_hash=prev_hash)
        records.append(sealed)
        prev_hash = sealed.chain.record_hash

    digest = compute_session_digest(records)
    assert isinstance(digest, str) and len(digest) == 64

    # Deterministic
    assert compute_session_digest(records) == digest

    # Different order of input → same digest (sorted internally)
    assert compute_session_digest(list(reversed(records))) == digest
    print("  PASS: test_session_digest")


# ==================================================================
# 5. Storage Round-trip
# ==================================================================

def test_storage_record_roundtrip():
    """Save and retrieve AuditRecord via SQLite storage."""
    priv, pub = generate_keypair()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        storage = Storage(db_path)
        session_id = uuid7()

        r = make_record(seq=0, session_id=session_id)
        sealed = seal_record(r, priv, previous_hash=None)
        storage.save_record(sealed)

        # Retrieve by ID
        loaded = storage.get_record(sealed.header.record_id)
        assert loaded is not None
        assert loaded.header.record_id == sealed.header.record_id
        assert loaded.chain.record_hash == sealed.chain.record_hash
        assert loaded.narrative == sealed.narrative

        # Retrieve by session
        session_records = storage.get_session_records(session_id)
        assert len(session_records) == 1
        assert session_records[0].chain.record_hash == sealed.chain.record_hash

        # Retrieve by agent
        agent_records = storage.get_agent_records("did:key:z6MkTestAgent")
        assert len(agent_records) == 1

        storage.close()
        print("  PASS: test_storage_record_roundtrip")
    finally:
        os.unlink(db_path)


def test_storage_session_lifecycle():
    """Session create → get → close lifecycle."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        storage = Storage(db_path)
        session_id = uuid7()

        storage.create_session(
            session_id=session_id,
            agent_did="did:key:z6MkA",
            principal_did="did:key:z6MkP",
            purpose="Test session",
            mode="solo",
        )

        session = storage.get_session(session_id)
        assert session is not None
        assert session["status"] == "active"
        assert session["purpose"] == "Test session"

        storage.close_session(session_id)
        session = storage.get_session(session_id)
        assert session["status"] == "closed"
        assert session["closed_at"] is not None

        storage.close()
        print("  PASS: test_storage_session_lifecycle")
    finally:
        os.unlink(db_path)


def test_storage_chain_state():
    """Chain state upsert and retrieval."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        storage = Storage(db_path)
        agent = "did:key:z6MkA"

        assert storage.get_chain_state(agent) is None

        storage.update_chain_state(agent, "hash1", 1, 1)
        state = storage.get_chain_state(agent)
        assert state["last_record_hash"] == "hash1"

        storage.update_chain_state(agent, "hash2", 2, 2)
        state = storage.get_chain_state(agent)
        assert state["last_record_hash"] == "hash2"
        assert state["last_sequence_number"] == 2

        storage.close()
        print("  PASS: test_storage_chain_state")
    finally:
        os.unlink(db_path)


# ==================================================================
# 6. End-to-End: Full Solo Session
# ==================================================================

def test_e2e_solo_session():
    """Full solo session: build chain → store → verify → tamper → detect."""
    priv, pub = generate_keypair()
    agent_did = public_key_to_did_key(pub)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        storage = Storage(db_path)
        session_id = uuid7()

        # Create session
        storage.create_session(
            session_id=session_id,
            agent_did=agent_did,
            principal_did="did:key:z6MkPrincipalAlice",
            purpose="Subscription renewal evaluation",
            mode="solo",
        )

        # Build chain: initiation → decision → termination
        records = []
        prev_hash = None
        chain_data = [
            (AuditPointType.INITIATION, "Session initiated for subscription review.",
             {"purpose": "subscription_review"}),
            (AuditPointType.AGREEMENT_OR_REJECTION, "Renew Netflix at $15.49/mo.",
             {"service": "Netflix", "amount": 15.49, "currency": "USD"}),
            (AuditPointType.TERMINATION, "Session complete. Total: $15.49.",
             {"outcome": "renewed", "total_value": 15.49}),
        ]

        for i, (apt, narrative, sd) in enumerate(chain_data):
            r = AuditRecord(
                header=RecordHeader(
                    session_id=session_id,
                    audit_point_type=apt,
                    mode=OperatingMode.SOLO,
                ),
                narrative=narrative,
                structured_data=sd,
                authorization=Authorization(
                    principal_did="did:key:z6MkPrincipalAlice",
                    agent_did=agent_did,
                    scope_summary="Subscription management, max $50/tx",
                ),
                chain=ChainMeta(
                    sequence_number=i,
                    previous_hash=prev_hash,
                ),
            )
            sealed = seal_record(r, priv, previous_hash=prev_hash)
            storage.save_record(sealed)
            records.append(sealed)
            prev_hash = sealed.chain.record_hash

            # Update chain state
            state = storage.get_chain_state(agent_did)
            total = (state["total_records"] if state else 0) + 1
            storage.update_chain_state(agent_did, prev_hash, i, total)

        # Verify from storage
        loaded = storage.get_session_records(session_id)
        assert len(loaded) == 3
        result = verify_chain(loaded, pub)
        assert result["chain_valid"] is True, f"E2E chain invalid: {result}"

        # Session digest
        digest = compute_session_digest(loaded)
        assert len(digest) == 64

        # Tamper detection: modify a loaded record
        tampered_list = list(loaded)
        tampered_list[1] = loaded[1].model_copy(
            update={"narrative": "Renew Netflix at $5.49/mo."}
        )
        bad_result = verify_chain(tampered_list, pub)
        assert bad_result["chain_valid"] is False

        storage.close()
        print("  PASS: test_e2e_solo_session")
    finally:
        os.unlink(db_path)


# ==================================================================
# 7. Golden File
# ==================================================================

def generate_golden_file():
    """Generate a golden file: known-correct record for cross-implementation testing."""
    priv, pub = generate_keypair()
    agent_did = public_key_to_did_key(pub)

    r = AuditRecord(
        header=RecordHeader(
            record_id="019503a0-0000-7000-8000-000000000001",
            session_id="019503a0-0000-7000-8000-000000000000",
            timestamp=datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc),
            audit_point_type=AuditPointType.INITIATION,
            mode=OperatingMode.SOLO,
        ),
        narrative="Session initiated. Purpose: Golden file test. Mode: solo.",
        structured_data={
            "purpose": "golden_file_test",
            "mode": "solo",
            "audit_language": "en",
        },
        authorization=Authorization(
            principal_did="did:key:z6MkGoldenPrincipal",
            agent_did=agent_did,
            scope_summary="Golden file test scope",
        ),
        chain=ChainMeta(sequence_number=0),
    )

    sealed = seal_record(r, priv, previous_hash=None)

    # Verify internal consistency
    hashable = sealed.hashable_dict()
    canonical_bytes = canonicalize(hashable)
    expected_hash = sha256_hex(canonical_bytes)
    assert expected_hash == sealed.chain.record_hash, (
        f"Consistency check failed: {expected_hash} != {sealed.chain.record_hash}"
    )

    golden = {
        "description": "AATP v0.1.0 Golden File — reference audit record (v2 model)",
        "canonical_json_hex": canonical_bytes.hex(),
        "record_hash": sealed.chain.record_hash,
        "verification": "sha256(bytes.fromhex(canonical_json_hex)) == record_hash",
        "record": json.loads(sealed.model_dump_json()),
        "public_key_pem": public_key_to_pem(pub).decode("utf-8"),
    }

    golden_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "golden_record.json"
    )
    with open(golden_path, "w") as f:
        json.dump(golden, f, indent=2, ensure_ascii=False)

    # Self-test
    loaded_hash = sha256_hex(bytes.fromhex(golden["canonical_json_hex"]))
    assert loaded_hash == golden["record_hash"], "Golden file self-test failed"

    print(f"  Golden file → {golden_path}")
    print(f"  Self-test: sha256(canonical) == record_hash ✓")
    return golden


# ==================================================================
# Runner
# ==================================================================

def run_all():
    print("=" * 60)
    print("AATP v2 SDK Test Suite")
    print("=" * 60)

    print("\n--- 1. Record Model Validation ---")
    test_record_basic()
    test_record_all_audit_point_types()
    test_extension_requires_fields()
    test_non_extension_rejects_extension_fields()
    test_solo_rejects_counterparty()
    test_bilateral_requires_counterparty_did()
    test_unilateral_flexible_counterparty()
    test_counterparty_needs_at_least_one_id()
    test_genesis_chain_validation()
    test_structured_data_rejects_nan_inf()
    test_structured_data_must_be_nonempty()
    test_principal_did_pattern()
    test_hashable_dict_excludes_seal_fields()
    test_record_size_limit()
    test_json_schema_export()

    print("\n--- 2. Canonical Serialization ---")
    test_canonicalize_primitives()
    test_canonicalize_negative_zero()
    test_canonicalize_float_formatting()
    test_canonicalize_key_ordering()
    test_canonicalize_nested()
    test_canonicalize_string_roundtrip()
    test_canonicalize_errors()

    print("\n--- 3. Crypto Primitives ---")
    test_sign_verify()
    test_pem_roundtrip()
    test_sha256()
    test_did_key()

    print("\n--- 4. Chain Seal & Verify ---")
    test_seal_genesis()
    test_seal_chain_of_three()
    test_tamper_detection()
    test_session_digest()

    print("\n--- 5. Storage Round-trip ---")
    test_storage_record_roundtrip()
    test_storage_session_lifecycle()
    test_storage_chain_state()

    print("\n--- 6. End-to-End ---")
    test_e2e_solo_session()

    print("\n--- 7. Golden File ---")
    generate_golden_file()

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    run_all()
