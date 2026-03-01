"""
tools/dashboard.py — AATP Debug Dashboard (Flask)

Local development dashboard for visualizing audit chains, decisions,
audit reports, and debug information.

Run:
    cd aatp-protocol
    python tools/dashboard.py

Then open http://localhost:5000 in your browser.

Data sources (all from examples/output/):
    - trail_llm.json       → audit chain records
    - llm_responses.json   → raw LLM call data + token usage
    - audit_report.json    → L1/L2/L3 audit results
    - purpose_chain.json   → purpose chain linkage (if present)
"""

import json
import os
import sys
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

# Resolve project root (tools/dashboard.py → project root)
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent  # tools/ → project root
OUTPUT_DIR = PROJECT_ROOT / "examples" / "output"

app = Flask(__name__, static_folder=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(filename: str):
    """Load a JSON file from OUTPUT_DIR, return None if missing."""
    path = OUTPUT_DIR / filename
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _build_sessions(trail: list) -> dict:
    """Group trail records by session_id, compute per-session metadata."""
    sessions = {}
    for rec in trail:
        sid = rec["header"]["session_id"]
        if sid not in sessions:
            sessions[sid] = {
                "session_id": sid,
                "records": [],
                "record_count": 0,
                "first_seq": None,
                "last_seq": None,
                "purpose": None,
                "upstream_session_id": None,
                "deployer_objective": None,
                "mode": rec["header"]["mode"],
                "outcome_summary": None,
                "has_initiation": False,
                "has_termination": False,
            }

        s = sessions[sid]
        s["records"].append(rec)
        s["record_count"] += 1

        seq = rec["chain"]["sequence_number"]
        if s["first_seq"] is None or seq < s["first_seq"]:
            s["first_seq"] = seq
        if s["last_seq"] is None or seq > s["last_seq"]:
            s["last_seq"] = seq

        apt = rec["header"]["audit_point_type"]
        if apt == "initiation":
            s["has_initiation"] = True
            sd = rec["structured_data"]
            s["purpose"] = sd.get("purpose")
            s["upstream_session_id"] = sd.get("upstream_session_id")
            s["deployer_objective"] = sd.get("deployer_objective")
        elif apt == "termination":
            s["has_termination"] = True
            sd = rec["structured_data"]
            s["outcome_summary"] = sd.get("outcome_summary")

    return sessions


def _build_chain_verification(trail: list) -> dict:
    """Verify hash chain linkage and sequence continuity."""
    results = {
        "total_records": len(trail),
        "sequence_gaps": [],
        "hash_breaks": [],
        "chain_valid": True,
    }

    for i, rec in enumerate(trail):
        seq = rec["chain"]["sequence_number"]
        prev_hash = rec["chain"]["previous_hash"]

        # Check sequence continuity
        if i == 0:
            if seq != 0:
                results["sequence_gaps"].append({
                    "index": i,
                    "expected": 0,
                    "got": seq,
                })
        else:
            expected = trail[i - 1]["chain"]["sequence_number"] + 1
            if seq != expected:
                results["sequence_gaps"].append({
                    "index": i,
                    "expected": expected,
                    "got": seq,
                })

        # Check hash linkage
        if i == 0:
            if prev_hash is not None:
                results["hash_breaks"].append({
                    "index": i,
                    "detail": "First record should have null previous_hash",
                })
        else:
            expected_hash = trail[i - 1]["chain"]["record_hash"]
            if prev_hash != expected_hash:
                results["hash_breaks"].append({
                    "index": i,
                    "expected": expected_hash[:16] + "...",
                    "got": (prev_hash or "null")[:16] + "...",
                })

    if results["sequence_gaps"] or results["hash_breaks"]:
        results["chain_valid"] = False

    return results


def _build_purpose_tree(sessions: dict) -> dict:
    """Build a tree structure from session purpose chain linkages."""
    # Find root session(s) — those with deployer_objective set
    roots = []
    children_map = {}  # upstream_id -> [child sessions]

    for sid, s in sessions.items():
        upstream = s["upstream_session_id"]
        if upstream:
            if upstream not in children_map:
                children_map[upstream] = []
            children_map[upstream].append(sid)
        elif s["deployer_objective"]:
            roots.append(sid)

    def _build_node(sid):
        s = sessions[sid]
        # Find the business record (not INIT/TERM)
        business_records = [
            r for r in s["records"]
            if r["header"]["audit_point_type"] not in ("initiation", "termination")
        ]
        decision = None
        if business_records:
            br = business_records[0]
            decision = {
                "audit_point_type": br["header"]["audit_point_type"],
                "action": br["structured_data"].get("action"),
                "narrative_preview": br["narrative"][:120] + "..."
                    if len(br["narrative"]) > 120 else br["narrative"],
            }

        node = {
            "session_id": sid,
            "purpose": s["purpose"],
            "record_count": s["record_count"],
            "outcome_summary": s["outcome_summary"],
            "decision": decision,
            "children": [],
        }

        for child_sid in children_map.get(sid, []):
            node["children"].append(_build_node(child_sid))

        return node

    tree = [_build_node(r) for r in roots]
    return {"roots": tree, "total_sessions": len(sessions)}


def _build_token_summary(responses: list) -> dict:
    """Summarize token usage from LLM responses."""
    total_prompt = 0
    total_completion = 0
    total_tokens = 0
    calls = []

    for r in responses:
        usage = r.get("usage", {})
        pt = usage.get("prompt_tokens", 0)
        ct = usage.get("completion_tokens", 0)
        tt = usage.get("total_tokens", 0)
        total_prompt += pt
        total_completion += ct
        total_tokens += tt

        calls.append({
            "call_type": r.get("call_type"),
            "event_id": r.get("event_id"),
            "session_purpose": r.get("session_purpose"),
            "model": r.get("model"),
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "total_tokens": tt,
        })

    return {
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_tokens": total_tokens,
        "total_calls": len(calls),
        "calls": calls,
    }


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the dashboard HTML."""
    template_dir = SCRIPT_DIR / "templates"
    return send_from_directory(str(template_dir), "dashboard.html")


@app.route("/api/overview")
def api_overview():
    """High-level overview: session count, record count, chain status."""
    trail = _load_json("trail_llm.json")
    responses = _load_json("llm_responses.json")
    report = _load_json("audit_report.json")

    if not trail:
        return jsonify({"error": "trail_llm.json not found"}), 404

    sessions = _build_sessions(trail)
    chain_check = _build_chain_verification(trail)
    token_summary = _build_token_summary(responses or [])

    return jsonify({
        "total_records": len(trail),
        "total_sessions": len(sessions),
        "chain_valid": chain_check["chain_valid"],
        "sequence_gaps": len(chain_check["sequence_gaps"]),
        "hash_breaks": len(chain_check["hash_breaks"]),
        "has_audit_report": report is not None,
        "l3_scores": report.get("l3_scores") if report else None,
        "token_summary": {
            "total_tokens": token_summary["total_tokens"],
            "total_calls": token_summary["total_calls"],
        },
    })


@app.route("/api/chain")
def api_chain():
    """Purpose chain tree + per-session data."""
    trail = _load_json("trail_llm.json")
    if not trail:
        return jsonify({"error": "trail_llm.json not found"}), 404

    sessions = _build_sessions(trail)
    tree = _build_purpose_tree(sessions)
    return jsonify(tree)


@app.route("/api/sessions")
def api_sessions():
    """All sessions with their records."""
    trail = _load_json("trail_llm.json")
    if not trail:
        return jsonify({"error": "trail_llm.json not found"}), 404

    sessions = _build_sessions(trail)
    # Convert to list, sorted by first_seq
    session_list = sorted(sessions.values(), key=lambda s: s["first_seq"])
    return jsonify(session_list)


@app.route("/api/session/<session_id>")
def api_session_detail(session_id):
    """Single session with full record details."""
    trail = _load_json("trail_llm.json")
    if not trail:
        return jsonify({"error": "trail_llm.json not found"}), 404

    sessions = _build_sessions(trail)
    if session_id not in sessions:
        return jsonify({"error": f"Session {session_id} not found"}), 404

    return jsonify(sessions[session_id])


@app.route("/api/decisions")
def api_decisions():
    """All decision records with LLM response data merged."""
    trail = _load_json("trail_llm.json")
    responses = _load_json("llm_responses.json")
    if not trail:
        return jsonify({"error": "trail_llm.json not found"}), 404

    # Build event_id → LLM response lookup
    llm_lookup = {}
    if responses:
        for r in responses:
            eid = r.get("event_id")
            if eid:
                llm_lookup[eid] = r

    # Find business records (not INIT/TERM) from downstream sessions
    sessions = _build_sessions(trail)
    decisions = []

    for sid, s in sorted(sessions.items(), key=lambda x: x[1]["first_seq"]):
        for rec in s["records"]:
            apt = rec["header"]["audit_point_type"]
            if apt in ("initiation", "termination"):
                continue

            # Try to match with LLM response via purpose → event_id
            llm_data = None
            purpose = s.get("purpose", "")
            for eid, lr in llm_lookup.items():
                if lr.get("session_purpose") == purpose:
                    llm_data = lr
                    break

            decisions.append({
                "session_id": sid,
                "session_purpose": s["purpose"],
                "record_id": rec["header"]["record_id"],
                "audit_point_type": apt,
                "narrative": rec["narrative"],
                "structured_data": rec["structured_data"],
                "sequence_number": rec["chain"]["sequence_number"],
                "timestamp": rec["header"]["timestamp"],
                "llm_usage": llm_data.get("usage") if llm_data else None,
                "llm_model": llm_data.get("model") if llm_data else None,
            })

    return jsonify(decisions)


@app.route("/api/audit")
def api_audit():
    """Audit report data."""
    report = _load_json("audit_report.json")
    if not report:
        return jsonify({"error": "audit_report.json not found"}), 404
    return jsonify(report)


@app.route("/api/debug")
def api_debug():
    """Debug data: chain verification, raw records, sequence map."""
    trail = _load_json("trail_llm.json")
    if not trail:
        return jsonify({"error": "trail_llm.json not found"}), 404

    chain_check = _build_chain_verification(trail)

    # Build sequence map for visualization
    sequence_map = []
    for rec in trail:
        sequence_map.append({
            "seq": rec["chain"]["sequence_number"],
            "session_id": rec["header"]["session_id"][:8] + "...",
            "session_id_full": rec["header"]["session_id"],
            "type": rec["header"]["audit_point_type"],
            "record_hash_short": rec["chain"]["record_hash"][:12] + "...",
            "record_hash": rec["chain"]["record_hash"],
            "prev_hash_short": (rec["chain"]["previous_hash"][:12] + "...")
                if rec["chain"]["previous_hash"] else "null",
            "prev_hash": rec["chain"]["previous_hash"],
            "linked": True,  # will be overridden below if broken
        })

    # Mark broken links
    for brk in chain_check["hash_breaks"]:
        idx = brk["index"]
        if idx < len(sequence_map):
            sequence_map[idx]["linked"] = False

    return jsonify({
        "chain_verification": chain_check,
        "sequence_map": sequence_map,
    })


@app.route("/api/tokens")
def api_tokens():
    """Token usage breakdown."""
    responses = _load_json("llm_responses.json")
    if not responses:
        return jsonify({"error": "llm_responses.json not found"}), 404
    return jsonify(_build_token_summary(responses))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Verify output directory exists
    if not OUTPUT_DIR.exists():
        print(f"ERROR: Output directory not found: {OUTPUT_DIR}")
        print(f"Expected path: {OUTPUT_DIR}")
        print("Make sure you run this from the project root: python tools/dashboard.py")
        sys.exit(1)

    # Check for required files
    required = ["trail_llm.json"]
    missing = [f for f in required if not (OUTPUT_DIR / f).exists()]
    if missing:
        print(f"WARNING: Missing files in {OUTPUT_DIR}: {missing}")
        print("Dashboard will show errors for missing data sources.")

    print(f"AATP Debug Dashboard")
    print(f"  Output dir: {OUTPUT_DIR}")
    print(f"  Files found: {[f.name for f in OUTPUT_DIR.glob('*.json')]}")
    print(f"  URL: http://localhost:5000")
    print()

    app.run(debug=True, port=5000)
