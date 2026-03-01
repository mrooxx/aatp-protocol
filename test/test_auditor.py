"""
test/test_auditor.py — Tests for aatp_auditor (Stage 3.3)

Tests:
    import_trail_to_storage  (4 tests)
    _parse_auditor_response  (8 tests)
    AuditLLM.audit_session   (3 tests)

Run:  python test/test_auditor.py
"""

import json
import os
import sys
import tempfile
import traceback

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock, patch

from aatp_core.canonical import canonicalize
from aatp_core.crypto import (
    generate_keypair,
    public_key_to_did_key,
    sha256_hex,
)
from aatp_core.storage import Storage
from aatp_recorder import Recorder
from aatp_reviewer import Reviewer
from aatp_auditor import (
    AuditLLM,
    AuditorResponseError,
    import_trail_to_storage,
    _parse_auditor_response,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Agent keys
_agent_priv, _agent_pub = generate_keypair()
_agent_did = public_key_to_did_key(_agent_pub)
_principal_did = "did:example:human-principal-001"

# Auditor keys (independent — Invariant 6)
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
            "id": _agent_did,
            "scope": "manage subscriptions up to $50",
            "max_transaction_value": 50.00,
            "allowed_categories": ["subscription", "streaming"],
        },
    }


def _setup(db_path: str):
    """Create a recorder, reviewer, and storage sharing the same DB."""
    storage = Storage(db_path)
    vc = _make_vc()
    vc_hash = sha256_hex(canonicalize(vc))

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

    return recorder, reviewer, storage, vc


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
        narrative="Decided to keep Netflix at $15.99 monthly",
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


def _export_trail(storage: Storage, session_id: str, path: str) -> None:
    """Export session records to a JSON trail file."""
    records = storage.get_session_records(session_id)
    trail = [json.loads(r.model_dump_json()) for r in records]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(trail, f, indent=2, ensure_ascii=False)


def _cleanup(*paths) -> None:
    """Delete temp files, close storages."""
    for p in paths:
        try:
            if isinstance(p, Storage):
                p.close()
            elif isinstance(p, str) and os.path.exists(p):
                os.unlink(p)
        except Exception:
            pass


def _valid_llm_response(record_ids: list) -> str:
    """Return a valid auditor LLM JSON response string."""
    return json.dumps({
        "overall_score": 85,
        "integrity_score": 95,
        "conformance_score": 90,
        "reasonableness_score": 80,
        "findings": [
            {
                "record_refs": record_ids[:1],
                "severity": "info",
                "finding": "Session well-documented and within scope",
                "recommendation": "No action needed",
            },
        ],
        "recommendations": [
            "Consider documenting alternatives considered",
        ],
    })


# ---------------------------------------------------------------------------
# Tests: import_trail_to_storage
# ---------------------------------------------------------------------------

def test_import_trail_record_count():
    """import_trail_to_storage: correct record count and metadata."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        src_db = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dst_db = f.name
    trail_path = src_db + ".trail.json"

    try:
        # Create source session and export
        rec, _, src_storage, vc = _setup(src_db)
        sid = _create_sample_session(rec)
        _export_trail(src_storage, sid, trail_path)
        src_storage.close()

        # Import into fresh storage
        dst_storage = Storage(dst_db)
        result = import_trail_to_storage(trail_path, dst_storage)

        assert result["record_count"] == 4, f"Expected 4, got {result['record_count']}"
        assert result["session_id"] == sid
        assert result["agent_did"] == _agent_did
        assert result["principal_did"] == _principal_did
        assert result["status"] == "imported"

        dst_storage.close()
        _ok("test_import_trail_record_count")

    finally:
        _cleanup(src_db, dst_db, trail_path)


def test_import_trail_chain_state():
    """import_trail_to_storage: chain_state updated correctly."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        src_db = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dst_db = f.name
    trail_path = src_db + ".trail.json"

    try:
        rec, _, src_storage, vc = _setup(src_db)
        sid = _create_sample_session(rec)

        # Get expected last hash/seq from source
        src_records = src_storage.get_session_records(sid)
        expected_last_hash = src_records[-1].chain.record_hash
        expected_last_seq = src_records[-1].chain.sequence_number

        _export_trail(src_storage, sid, trail_path)
        src_storage.close()

        # Import
        dst_storage = Storage(dst_db)
        import_trail_to_storage(trail_path, dst_storage)

        state = dst_storage.get_chain_state(_agent_did)
        assert state is not None, "chain_state missing"
        assert state["last_record_hash"] == expected_last_hash
        assert state["last_sequence_number"] == expected_last_seq
        assert state["total_records"] == 4

        dst_storage.close()
        _ok("test_import_trail_chain_state")

    finally:
        _cleanup(src_db, dst_db, trail_path)


def test_import_trail_session_closed():
    """import_trail_to_storage: session closed when termination present."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        src_db = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dst_db = f.name
    trail_path = src_db + ".trail.json"

    try:
        rec, _, src_storage, vc = _setup(src_db)
        sid = _create_sample_session(rec)  # includes termination
        _export_trail(src_storage, sid, trail_path)
        src_storage.close()

        dst_storage = Storage(dst_db)
        import_trail_to_storage(trail_path, dst_storage)

        # Reviewer should be able to get session for review (requires closed)
        reviewer = Reviewer(
            auditor_did=_auditor_did,
            auditor_private_key=_auditor_priv,
            storage=dst_storage,
        )
        session_data = reviewer.get_session_for_review(sid)
        assert "error" not in session_data, f"Unexpected error: {session_data.get('error')}"
        assert session_data["status"] == "closed"

        dst_storage.close()
        _ok("test_import_trail_session_closed")

    finally:
        _cleanup(src_db, dst_db, trail_path)


def test_import_trail_empty_file():
    """import_trail_to_storage: empty trail raises ValueError."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dst_db = f.name
    trail_path = dst_db + ".empty.json"

    try:
        with open(trail_path, "w") as f:
            json.dump([], f)

        dst_storage = Storage(dst_db)
        try:
            import_trail_to_storage(trail_path, dst_storage)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "empty" in str(e).lower()

        dst_storage.close()
        _ok("test_import_trail_empty_file")

    finally:
        _cleanup(dst_db, trail_path)


# ---------------------------------------------------------------------------
# Tests: _parse_auditor_response
# ---------------------------------------------------------------------------

def test_parse_valid_response():
    """_parse_auditor_response: valid input returns correct dict."""
    raw = _valid_llm_response(["rec-001"])
    result = _parse_auditor_response(raw)

    assert result["overall_score"] == 85
    assert result["integrity_score"] == 95
    assert result["conformance_score"] == 90
    assert result["reasonableness_score"] == 80
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "info"
    assert len(result["recommendations"]) == 1

    _ok("test_parse_valid_response")


def test_parse_invalid_json():
    """_parse_auditor_response: invalid JSON raises AuditorResponseError."""
    try:
        _parse_auditor_response("not json at all {{{")
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "invalid JSON" in str(e)

    _ok("test_parse_invalid_json")


def test_parse_missing_score_field():
    """_parse_auditor_response: missing score field raises error."""
    data = {
        "overall_score": 85,
        # missing integrity_score
        "conformance_score": 90,
        "reasonableness_score": 80,
        "findings": [
            {"record_refs": ["r1"], "severity": "info", "finding": "ok"},
        ],
        "recommendations": [],
    }
    try:
        _parse_auditor_response(json.dumps(data))
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "integrity_score" in str(e)

    _ok("test_parse_missing_score_field")


def test_parse_score_out_of_range():
    """_parse_auditor_response: score > 100 or < 0 raises error."""
    # Score > 100
    data = {
        "overall_score": 150,
        "integrity_score": 95,
        "conformance_score": 90,
        "reasonableness_score": 80,
        "findings": [
            {"record_refs": ["r1"], "severity": "info", "finding": "ok"},
        ],
        "recommendations": [],
    }
    try:
        _parse_auditor_response(json.dumps(data))
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "0-100" in str(e)

    # Score < 0
    data["overall_score"] = -5
    try:
        _parse_auditor_response(json.dumps(data))
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "0-100" in str(e)

    _ok("test_parse_score_out_of_range")


def test_parse_score_float_rejected():
    """_parse_auditor_response: float score raises error."""
    data = {
        "overall_score": 85.5,
        "integrity_score": 95,
        "conformance_score": 90,
        "reasonableness_score": 80,
        "findings": [
            {"record_refs": ["r1"], "severity": "info", "finding": "ok"},
        ],
        "recommendations": [],
    }
    try:
        _parse_auditor_response(json.dumps(data))
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "0-100" in str(e)

    _ok("test_parse_score_float_rejected")


def test_parse_empty_findings():
    """_parse_auditor_response: empty findings list raises error."""
    data = {
        "overall_score": 85,
        "integrity_score": 95,
        "conformance_score": 90,
        "reasonableness_score": 80,
        "findings": [],
        "recommendations": [],
    }
    try:
        _parse_auditor_response(json.dumps(data))
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "non-empty" in str(e)

    _ok("test_parse_empty_findings")


def test_parse_finding_missing_record_refs():
    """_parse_auditor_response: finding without record_refs raises error."""
    data = {
        "overall_score": 85,
        "integrity_score": 95,
        "conformance_score": 90,
        "reasonableness_score": 80,
        "findings": [
            {"severity": "info", "finding": "Missing refs"},
        ],
        "recommendations": [],
    }
    try:
        _parse_auditor_response(json.dumps(data))
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "record_refs" in str(e)

    _ok("test_parse_finding_missing_record_refs")


def test_parse_finding_invalid_severity():
    """_parse_auditor_response: invalid severity raises error."""
    data = {
        "overall_score": 85,
        "integrity_score": 95,
        "conformance_score": 90,
        "reasonableness_score": 80,
        "findings": [
            {
                "record_refs": ["r1"],
                "severity": "urgent",  # invalid
                "finding": "Something bad",
            },
        ],
        "recommendations": [],
    }
    try:
        _parse_auditor_response(json.dumps(data))
        assert False, "Should have raised AuditorResponseError"
    except AuditorResponseError as e:
        assert "severity" in str(e)

    _ok("test_parse_finding_invalid_severity")


# ---------------------------------------------------------------------------
# Tests: AuditLLM.audit_session (mock OpenAI)
# ---------------------------------------------------------------------------

def _make_mock_openai_response(content: str):
    """Build a mock OpenAI chat completion response object."""
    mock_message = MagicMock()
    mock_message.content = content

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_usage = MagicMock()
    mock_usage.prompt_tokens = 1000
    mock_usage.completion_tokens = 200
    mock_usage.total_tokens = 1200

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.usage = mock_usage

    return mock_response


def test_audit_session_full_flow():
    """AuditLLM.audit_session: mock LLM, full L1->L2->L3, correct structure."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        src_db = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dst_db = f.name
    trail_path = src_db + ".trail.json"

    try:
        # Create and export a session
        rec, _, src_storage, vc = _setup(src_db)
        sid = _create_sample_session(rec)
        src_records = src_storage.get_session_records(sid)
        record_ids = [r.header.record_id for r in src_records]
        _export_trail(src_storage, sid, trail_path)
        src_storage.close()

        # Import into fresh storage
        dst_storage = Storage(dst_db)
        import_trail_to_storage(trail_path, dst_storage)

        # Set up reviewer + mock AuditLLM
        reviewer = Reviewer(
            auditor_did=_auditor_did,
            auditor_private_key=_auditor_priv,
            storage=dst_storage,
        )

        mock_llm_response = _valid_llm_response(record_ids)
        mock_openai_response = _make_mock_openai_response(mock_llm_response)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_openai_response

        # Patch OpenAI so AuditLLM.__init__ doesn't need a real key
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-fake"}):
            with patch("aatp_auditor.OpenAI", return_value=mock_client):
                auditor = AuditLLM(reviewer=reviewer)

        result = auditor.audit_session(
            session_id=sid,
            agent_did=_agent_did,
            agent_public_key=_agent_pub,
            authorization_vc=vc,
        )

        # Verify return structure
        assert "l1_result" in result
        assert "l1_transitions" in result
        assert "l2_result" in result
        assert "l3_scores" in result
        assert "l3_findings" in result
        assert "l3_recommendations" in result
        assert "l3_submit_result" in result
        assert "token_usage" in result

        # Verify scores
        assert result["l3_scores"]["overall"] == 85
        assert result["l3_scores"]["integrity"] == 95

        # Verify L1
        assert result["l1_result"]["chain_valid"] is True

        # Verify token usage
        assert result["token_usage"]["total_tokens"] == 1200

        dst_storage.close()
        _ok("test_audit_session_full_flow")

    finally:
        _cleanup(src_db, dst_db, trail_path)


def test_audit_session_review_stored():
    """AuditLLM.audit_session: review is stored in Storage."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        src_db = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dst_db = f.name
    trail_path = src_db + ".trail.json"

    try:
        rec, _, src_storage, vc = _setup(src_db)
        sid = _create_sample_session(rec)
        src_records = src_storage.get_session_records(sid)
        record_ids = [r.header.record_id for r in src_records]
        _export_trail(src_storage, sid, trail_path)
        src_storage.close()

        dst_storage = Storage(dst_db)
        import_trail_to_storage(trail_path, dst_storage)

        reviewer = Reviewer(
            auditor_did=_auditor_did,
            auditor_private_key=_auditor_priv,
            storage=dst_storage,
        )

        mock_llm_response = _valid_llm_response(record_ids)
        mock_openai_response = _make_mock_openai_response(mock_llm_response)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_openai_response

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-fake"}):
            with patch("aatp_auditor.OpenAI", return_value=mock_client):
                auditor = AuditLLM(reviewer=reviewer)

        auditor.audit_session(
            session_id=sid,
            agent_did=_agent_did,
            agent_public_key=_agent_pub,
            authorization_vc=vc,
        )

        # Verify review is in storage
        reviews = dst_storage.get_session_reviews(sid)
        assert len(reviews) == 1, f"Expected 1 review, got {len(reviews)}"
        assert reviews[0]["signature"]["signer"] == _auditor_did

        dst_storage.close()
        _ok("test_audit_session_review_stored")

    finally:
        _cleanup(src_db, dst_db, trail_path)


def test_audit_session_invalid_llm_response():
    """AuditLLM.audit_session: invalid LLM JSON raises AuditorResponseError."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        src_db = f.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dst_db = f.name
    trail_path = src_db + ".trail.json"

    try:
        rec, _, src_storage, vc = _setup(src_db)
        sid = _create_sample_session(rec)
        _export_trail(src_storage, sid, trail_path)
        src_storage.close()

        dst_storage = Storage(dst_db)
        import_trail_to_storage(trail_path, dst_storage)

        reviewer = Reviewer(
            auditor_did=_auditor_did,
            auditor_private_key=_auditor_priv,
            storage=dst_storage,
        )

        # LLM returns garbage
        bad_response = _make_mock_openai_response('{"garbage": true}')

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = bad_response

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-fake"}):
            with patch("aatp_auditor.OpenAI", return_value=mock_client):
                auditor = AuditLLM(reviewer=reviewer)

        try:
            auditor.audit_session(
                session_id=sid,
                agent_did=_agent_did,
                agent_public_key=_agent_pub,
                authorization_vc=vc,
            )
            assert False, "Should have raised AuditorResponseError"
        except AuditorResponseError:
            pass  # expected

        dst_storage.close()
        _ok("test_audit_session_invalid_llm_response")

    finally:
        _cleanup(src_db, dst_db, trail_path)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("AATP Auditor Tests (Stage 3.3)")
    print("=" * 60)

    tests = [
        # import_trail_to_storage (4)
        test_import_trail_record_count,
        test_import_trail_chain_state,
        test_import_trail_session_closed,
        test_import_trail_empty_file,
        # _parse_auditor_response (8)
        test_parse_valid_response,
        test_parse_invalid_json,
        test_parse_missing_score_field,
        test_parse_score_out_of_range,
        test_parse_score_float_rejected,
        test_parse_empty_findings,
        test_parse_finding_missing_record_refs,
        test_parse_finding_invalid_severity,
        # AuditLLM.audit_session (3)
        test_audit_session_full_flow,
        test_audit_session_review_stored,
        test_audit_session_invalid_llm_response,
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
