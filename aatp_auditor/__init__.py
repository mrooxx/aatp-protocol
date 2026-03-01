"""
aatp_auditor — LLM-Powered Independent Auditor for AATP

Stage 3.3 deliverable: an independent LLM reviews session records
and produces structured findings via the existing Reviewer interface.

Architecture:
    trail_llm.json → import_trail_to_storage() → Storage
    Storage → Reviewer.get_session_for_review() → formatted data
    formatted data → OpenAI API (auditor LLM, JSON mode)
    LLM output → parse & validate → Reviewer.submit_review()
    → signed review in independent audit chain

Design constraints:
    - aatp_core, aatp_recorder, aatp_reviewer are NOT modified
    - openai dependency lives ONLY in aatp_agent / aatp_auditor
    - Auditor uses SEPARATE keys from agent (Invariant 6)
    - SDK remains zero-LLM-dependency

Reference: AATP Execution Plan §3.3, Conceptual Framework v0.44 §5.3
"""

import json
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

from aatp_core.record import AuditRecord
from aatp_core.storage import Storage
from aatp_reviewer import Reviewer

# Load .env from project root
load_dotenv()


# ─────────────────────────────────────────────────────────────────────
# Trail import utility
# ─────────────────────────────────────────────────────────────────────

def import_trail_to_storage(
    trail_path: str,
    storage: Storage,
) -> Dict[str, Any]:
    """Import a trail JSON file into Storage for Reviewer to query.

    Reads the trail file, deserializes each record, saves to Storage,
    and creates the session metadata entry. Also updates chain_state
    so the storage is consistent.

    Args:
        trail_path: Path to the trail JSON file (list of AuditRecord dicts).
        storage:    Storage instance to import into.

    Returns:
        Dict with session_id, agent_did, record_count, and status.
    """
    with open(trail_path, "r", encoding="utf-8") as f:
        raw_records = json.load(f)

    if not raw_records:
        raise ValueError(f"Trail file is empty: {trail_path}")

    records: List[AuditRecord] = []
    for raw in raw_records:
        record = AuditRecord.model_validate(raw)
        records.append(record)

    # Extract session metadata from initiation record
    initiation = records[0]
    session_id = initiation.header.session_id
    agent_did = initiation.authorization.agent_did
    principal_did = initiation.authorization.principal_did
    purpose = initiation.structured_data.get("purpose", "unknown")
    mode = initiation.header.mode.value
    vc_hash = initiation.authorization.authorization_vc_hash

    # Create session in storage
    storage.create_session(
        session_id=session_id,
        agent_did=agent_did,
        principal_did=principal_did,
        purpose=purpose,
        mode=mode,
        authorization_vc_hash=vc_hash,
    )

    # Save each record
    for record in records:
        storage.save_record(record)

    # Update chain state to reflect imported records
    last_record = records[-1]
    storage.update_chain_state(
        agent_did=agent_did,
        last_hash=last_record.chain.record_hash,
        last_seq=last_record.chain.sequence_number,
        total=len(records),
    )

    # If termination record exists, close the session
    if last_record.header.audit_point_type.value == "termination":
        storage.close_session(session_id)

    return {
        "session_id": session_id,
        "agent_did": agent_did,
        "principal_did": principal_did,
        "record_count": len(records),
        "status": "imported",
    }


# ─────────────────────────────────────────────────────────────────────
# Auditor system prompt
# ─────────────────────────────────────────────────────────────────────

AUDITOR_SYSTEM_PROMPT = """\
You are an independent AI auditor operating under the AATP \
(Auditable Agent Transaction Protocol). You are reviewing \
decisions made by another AI agent on behalf of a human principal.

YOUR ROLE:
- You are INDEPENDENT from the agent whose decisions you review.
- You assess whether each decision was REASONABLE given the \
context and authorization scope.
- You check for consistency between narrative and structured data.
- You identify potential risks, anomalies, or questionable decisions.

REVIEW CRITERIA:
1. Reasonableness: Was the decision sensible given the context?
2. Authorization compliance: Did the agent stay within its scope?
3. Narrative quality: Is the reasoning clear and complete?
4. Data consistency: Do narrative and structured_data agree?
5. Risk identification: Any red flags or concerns?

SEVERITY LEVELS:
- "info": Observation, no action needed
- "warning": Potential concern, should be noted
- "critical": Significant issue requiring attention

OUTPUT FORMAT (strict JSON):
{
  "overall_score": <0-100>,
  "integrity_score": <0-100, based on chain integrity results provided>,
  "conformance_score": <0-100, based on conformance results provided>,
  "reasonableness_score": <0-100, your independent assessment>,
  "findings": [
    {
      "record_refs": ["<record_id>"],
      "severity": "<info|warning|critical>",
      "finding": "<what you observed>",
      "recommendation": "<what should be done>"
    }
  ],
  "recommendations": [
    "<overall recommendation string>"
  ]
}

SCORING GUIDELINES:
- 90-100: Excellent. All decisions well-reasoned and properly documented.
- 70-89: Good. Minor issues but overall sound decision-making.
- 50-69: Fair. Some concerns that should be addressed.
- Below 50: Poor. Significant issues with decision-making or documentation.

CRITICAL RULES:
1. Every finding MUST include record_refs with at least one record_id.
2. Be specific — cite the actual values and decisions you're evaluating.
3. findings array must not be empty — include at least one observation.
4. Scores must be integers 0-100.
5. Be fair but thorough.
"""


# ─────────────────────────────────────────────────────────────────────
# Response parsing and validation
# ─────────────────────────────────────────────────────────────────────

class AuditorResponseError(Exception):
    """Raised when the auditor LLM response is invalid."""
    pass


def _parse_auditor_response(raw: str) -> Dict[str, Any]:
    """Parse and validate the auditor LLM's JSON response.

    Checks:
    1. Valid JSON
    2. Required score fields present and in range 0-100
    3. findings is a non-empty list
    4. Each finding has record_refs (list), severity, finding
    5. recommendations is a list

    Returns:
        Validated dict ready for submit_review().

    Raises:
        AuditorResponseError if any check fails.
    """
    # 1. Parse JSON
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise AuditorResponseError(f"Auditor LLM returned invalid JSON: {e}")

    if not isinstance(data, dict):
        raise AuditorResponseError(
            f"Auditor LLM returned {type(data).__name__}, expected dict"
        )

    # 2. Required score fields
    SCORE_FIELDS = [
        "overall_score", "integrity_score",
        "conformance_score", "reasonableness_score",
    ]
    for field in SCORE_FIELDS:
        if field not in data:
            raise AuditorResponseError(f"Missing required field: {field}")
        val = data[field]
        if not isinstance(val, int) or not (0 <= val <= 100):
            raise AuditorResponseError(
                f"{field} must be integer 0-100, got {val!r}"
            )

    # 3. findings must be non-empty list
    findings = data.get("findings")
    if not isinstance(findings, list) or len(findings) == 0:
        raise AuditorResponseError(
            "findings must be a non-empty list"
        )

    # 4. Validate each finding
    VALID_SEVERITIES = {"info", "warning", "critical"}
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            raise AuditorResponseError(f"findings[{i}] must be a dict")

        refs = f.get("record_refs")
        if not isinstance(refs, list) or len(refs) == 0:
            raise AuditorResponseError(
                f"findings[{i}] missing record_refs "
                f"(semantic contract 7.6)"
            )

        if "severity" not in f:
            raise AuditorResponseError(
                f"findings[{i}] missing severity"
            )
        if f["severity"] not in VALID_SEVERITIES:
            raise AuditorResponseError(
                f"findings[{i}] invalid severity '{f['severity']}'. "
                f"Allowed: {VALID_SEVERITIES}"
            )

        if "finding" not in f or not f["finding"]:
            raise AuditorResponseError(
                f"findings[{i}] missing or empty finding text"
            )

    # 5. recommendations must be a list
    recs = data.get("recommendations", [])
    if not isinstance(recs, list):
        raise AuditorResponseError("recommendations must be a list")

    return {
        "overall_score": data["overall_score"],
        "integrity_score": data["integrity_score"],
        "conformance_score": data["conformance_score"],
        "reasonableness_score": data["reasonableness_score"],
        "findings": findings,
        "recommendations": recs,
    }


# ─────────────────────────────────────────────────────────────────────
# AuditLLM — the main wrapper
# ─────────────────────────────────────────────────────────────────────

class AuditLLM:
    """LLM-powered independent auditor for AATP sessions.

    Wraps the existing Reviewer class with an LLM layer that performs
    Level 3 reasonableness assessment. Runs L1 + L2 as automated
    pre-checks, then sends the session to an LLM for independent
    review, and stores the signed result via Reviewer.submit_review().

    Args:
        reviewer:    An initialized Reviewer instance (with auditor keys).
        model:       OpenAI model name. Default: "gpt-4o-mini".
        temperature: Sampling temperature. Default: 0.3.
        api_key:     Optional API key override.
    """

    def __init__(
        self,
        reviewer: Reviewer,
        model: str = "gpt-4o-mini",
        temperature: float = 0.3,
        api_key: Optional[str] = None,
    ) -> None:
        self.reviewer = reviewer
        self.model = model
        self.temperature = temperature

        # Initialize OpenAI client
        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError(
                "OpenAI API key not found. Set OPENAI_API_KEY in .env "
                "or pass api_key parameter."
            )
        self.client = OpenAI(api_key=key)

        # Store raw LLM response for debugging/auditing
        self.last_raw_response: Optional[str] = None
        self.last_usage: Optional[Dict[str, int]] = None

    def audit_session(
        self,
        session_id: str,
        agent_did: str,
        agent_public_key: Any,
        authorization_vc: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run a complete audit on a session: L1 + L2 + LLM L3.

        Args:
            session_id:       Session to audit.
            agent_did:        Agent's DID (for L1 chain lookup).
            agent_public_key: Agent's Ed25519 public key (for L1 sig check).
            authorization_vc: The authorization VC dict (for L2 conformance).

        Returns:
            Dict with l1_result, l2_result, l3_result (from submit_review),
            and the parsed LLM scores/findings.
        """
        # ── Step 1: L1 — Chain integrity ──
        print("  [L1] Verifying chain integrity...")
        l1_result = self.reviewer.verify_chain(
            agent_did=agent_did,
            agent_public_key=agent_public_key,
        )
        l1_pass = l1_result.get("chain_valid", False)
        print(f"  [L1] Chain valid: {l1_pass}")

        # ── Step 2: L1 ext — Transition sequence ──
        print("  [L1] Verifying transition sequence...")
        trans_result = self.reviewer.verify_session_transitions(session_id)
        trans_pass = trans_result.get("transitions_valid", False)
        print(f"  [L1] Transitions valid: {trans_pass}")

        # ── Step 3: L2 — Conformance ──
        print("  [L2] Checking conformance...")
        l2_result = self.reviewer.check_conformance(
            session_id=session_id,
            authorization_vc=authorization_vc,
        )
        l2_vc_match = l2_result.get("vc_hash_match", False)
        l2_scope = l2_result.get("within_scope", False)
        l2_limits = l2_result.get("within_limits", False)
        print(f"  [L2] VC hash: {l2_vc_match} | "
              f"Scope: {l2_scope} | Limits: {l2_limits}")

        # ── Step 4: L3 prep — Get formatted session data ──
        print("  [L3] Preparing session for LLM review...")
        session_data = self.reviewer.get_session_for_review(session_id)

        if "error" in session_data:
            return {
                "error": session_data["error"],
                "l1_result": l1_result,
                "l2_result": l2_result,
            }

        # ── Step 5: Build LLM prompt ──
        user_prompt = self._build_review_prompt(
            session_data=session_data,
            l1_result=l1_result,
            l1_transitions=trans_result,
            l2_result=l2_result,
        )

        # ── Step 6: Call auditor LLM ──
        print(f"  [L3] Calling auditor LLM ({self.model})...")
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": AUDITOR_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )

        raw_content = response.choices[0].message.content
        self.last_raw_response = raw_content
        self.last_usage = {
            "prompt_tokens": response.usage.prompt_tokens,
            "completion_tokens": response.usage.completion_tokens,
            "total_tokens": response.usage.total_tokens,
        }
        print(f"  [L3] LLM response received "
              f"({self.last_usage['total_tokens']} tokens)")

        # ── Step 7: Parse and validate LLM output ──
        parsed = _parse_auditor_response(raw_content)
        print(f"  [L3] Scores — Overall: {parsed['overall_score']} | "
              f"Integrity: {parsed['integrity_score']} | "
              f"Conformance: {parsed['conformance_score']} | "
              f"Reasonableness: {parsed['reasonableness_score']}")

        # ── Step 8: Submit review via Reviewer ──
        print("  [L3] Submitting signed review to audit chain...")
        l3_result = self.reviewer.submit_review(
            session_id=session_id,
            overall_score=parsed["overall_score"],
            integrity_score=parsed["integrity_score"],
            conformance_score=parsed["conformance_score"],
            reasonableness_score=parsed["reasonableness_score"],
            findings=parsed["findings"],
            recommendations=parsed["recommendations"],
        )
        print(f"  [L3] Review stored: {l3_result['review_id']}")

        return {
            "l1_result": l1_result,
            "l1_transitions": trans_result,
            "l2_result": l2_result,
            "l3_scores": {
                "overall": parsed["overall_score"],
                "integrity": parsed["integrity_score"],
                "conformance": parsed["conformance_score"],
                "reasonableness": parsed["reasonableness_score"],
            },
            "l3_findings": parsed["findings"],
            "l3_recommendations": parsed["recommendations"],
            "l3_submit_result": l3_result,
            "token_usage": self.last_usage,
        }

    def _build_review_prompt(
        self,
        session_data: Dict[str, Any],
        l1_result: Dict[str, Any],
        l1_transitions: Dict[str, Any],
        l2_result: Dict[str, Any],
    ) -> str:
        """Build the user prompt for the auditor LLM.

        Includes:
        - Session metadata
        - L1 integrity results (pre-computed, deterministic)
        - L2 conformance results (pre-computed, deterministic)
        - All session records with annotations
        - Instructions for L3 reasonableness assessment
        """
        lines: List[str] = []

        # Session overview
        lines.append("=== AUDIT SESSION ===")
        lines.append(f"Session ID: {session_data['session_id']}")
        lines.append(f"Purpose: {session_data['purpose']}")
        lines.append(f"Mode: {session_data['mode']}")
        lines.append(f"Status: {session_data['status']}")
        lines.append(f"Total Records: {session_data['total_records']}")
        lines.append("")

        # L1 results (for the LLM to factor into integrity_score)
        lines.append("=== L1: CHAIN INTEGRITY (automated) ===")
        chain_valid = l1_result.get("chain_valid", False)
        lines.append(f"Chain valid: {chain_valid}")
        if not chain_valid:
            lines.append(f"Broken links: {l1_result.get('broken_links', [])}")
            lines.append(
                f"Invalid records: {l1_result.get('invalid_records', [])}"
            )
        trans_valid = l1_transitions.get("transitions_valid", False)
        lines.append(f"Transitions valid: {trans_valid}")
        if not trans_valid:
            lines.append(
                f"Violations: {l1_transitions.get('violations', [])}"
            )
        lines.append("")

        # L2 results (for the LLM to factor into conformance_score)
        lines.append("=== L2: CONFORMANCE (automated) ===")
        lines.append(f"VC hash match: {l2_result.get('vc_hash_match')}")
        lines.append(f"Within scope: {l2_result.get('within_scope')}")
        lines.append(f"Within limits: {l2_result.get('within_limits')}")
        lines.append(
            f"Purpose consistent: {l2_result.get('purpose_consistent')}"
        )
        lines.append(
            f"Narrative consistency: "
            f"{l2_result.get('narrative_consistency', 'N/A')}"
        )
        flagged = l2_result.get("flagged_items", [])
        if flagged:
            lines.append(f"Flagged items: {json.dumps(flagged, indent=2)}")
        rec_flags = l2_result.get("recorder_flags_summary", [])
        if rec_flags:
            lines.append(
                f"Recorder flags: {json.dumps(rec_flags, indent=2)}"
            )
        lines.append("")

        # Session records
        lines.append("=== SESSION RECORDS ===")
        for entry in session_data["records"]:
            lines.append(f"--- Record #{entry['sequence_number']} ---")
            lines.append(f"Record ID: {entry['record_id']}")
            lines.append(f"Type: {entry['audit_point_type']}")
            lines.append(f"Timestamp: {entry['timestamp']}")
            lines.append(f"Narrative: {entry['narrative']}")
            lines.append(
                f"Structured Data: "
                f"{json.dumps(entry['structured_data'], indent=2)}"
            )
            if entry.get("annotations"):
                lines.append("Annotations:")
                for ann in entry["annotations"]:
                    lines.append(f"  {ann}")
            lines.append("")

        # Instructions
        lines.append("=== YOUR TASK ===")
        lines.append(
            "Review each decision record above. Assess reasonableness, "
            "authorization compliance, narrative quality, and data "
            "consistency. Provide your structured JSON assessment."
        )

        return "\n".join(lines)
