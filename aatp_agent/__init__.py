"""
aatp_agent — LLM-Powered Finance Agent for AATP

Stage 3.1–3.2 deliverable: a minimal wrapper that connects OpenAI's API
to the existing AATP Recorder, replacing the MockFinanceAgent.

Updated for Purpose Chain architecture (Stage 3, Notes 004):
  - Root session: LLM decomposes deployer objective into sub-goals
  - Downstream sessions: LLM handles one event per session
  - Each LLM call receives purpose context from the purpose chain

Updated for Context Field (Stage 3, Notes 006):
  - LLM outputs a "context" field in structured_data containing
    reference numbers used in reasoning (balances, limits, thresholds)
  - Enables cross-checking without false NUMERIC_MISMATCH flags

Architecture:
    Root:   deployer_objective + all events
            → OpenAI API (JSON mode)
            → goal decomposition plan (budget allocation + sub-tasks)

    Per-event: world_state + event + session_purpose
               → OpenAI API (JSON mode)
               → parse & validate response
               → recorder.record_decision()
               → update world_state

Design constraints:
    - aatp_core record schema is NOT modified
    - openai dependency lives ONLY in this package
    - SDK remains zero-LLM-dependency (Invariant 2 preserved)
    - Purpose chain fields (upstream_session_id, deployer_objective)
      are protocol-level conventions in INITIATION structured_data,
      injected via Recorder's initiation_extra parameter

Reference: AATP Execution Plan §3.1–3.2, Conceptual Framework v0.44,
           Architecture Addendum v0.1 §2–3
"""

import json
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

# Load .env from project root
load_dotenv()


# ─────────────────────────────────────────────────────────────────────
# Valid audit point types that the LLM is allowed to choose from.
# Excludes INITIATION, TERMINATION (session-managed) and
# PERIODIC_STATUS (agent doesn't generate these in event processing).
# ─────────────────────────────────────────────────────────────────────

ALLOWED_DECISION_TYPES = [
    "opening",
    "offer",
    "counter_offer",
    "agreement_or_rejection",
    "payment_sent",
    "payment_confirmed",
    "problem_or_dispute",
    "closing",
    "extension",
]


# ─────────────────────────────────────────────────────────────────────
# System prompt — Root session (goal decomposition only)
# ─────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_ROOT = """\
You are a personal finance AI agent operating under the AATP \
(Auditable Agent Transaction Protocol). You are performing \
GOAL DECOMPOSITION for a root session.

YOUR TASK:
- You receive the deployer's objective and a list of pending events.
- You must analyze all events and produce a budget allocation plan.
- You do NOT execute any actions (no payments, cancellations, etc.).
- You only plan: break the objective into sub-goals, one per event.

OUTPUT FORMAT (strict JSON):
{
  "plan_narrative": "<Your analysis of the deployer's objective and \
how you plan to address each event. Explain your budget allocation \
reasoning. An auditor must understand your planning logic.>",
  "allocations": [
    {
      "event_id": "<event ID from the input>",
      "purpose": "<specific purpose for this sub-task session, \
e.g. 'Pay electricity bill $127.50 to Pacific Gas & Electric'>",
      "category": "<category: bills, subscriptions, investments, \
scheduling, services, other>",
      "estimated_amount": <estimated dollar amount or null if N/A>,
      "priority": "<high, medium, low>"
    }
  ],
  "budget_summary": {
    "total_budget_available": <number>,
    "total_estimated_spend": <number>,
    "reserve": <number>
  }
}

PLANNING GUIDELINES:
- Each event gets exactly one allocation entry.
- purpose must be specific enough for an independent session.
- estimated_amount should reflect the expected cost (null for \
non-monetary events like scheduling).
- Ensure total_estimated_spend + reserve <= total_budget_available.
- When in doubt about an action, note it in the purpose \
(e.g. "Evaluate and flag for approval: AAPL investment $500").
"""


# ─────────────────────────────────────────────────────────────────────
# System prompt — Downstream session (one event per session)
# ─────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a personal finance AI agent operating under the AATP \
(Auditable Agent Transaction Protocol). Every decision you make \
is recorded in a tamper-evident audit chain and will be reviewed \
by an independent auditor.

YOUR ROLE:
- You manage one specific financial decision for your principal.
- You MUST act within your authorization scope.
- You MUST explain your reasoning clearly — an auditor will read it.
- This session has a specific purpose assigned by the planning phase. \
Stay focused on that purpose.

OUTPUT FORMAT (strict JSON):
You must respond with a single JSON object containing exactly these fields:

{
  "audit_point_type": "<one of: opening, offer, counter_offer, \
agreement_or_rejection, payment_sent, payment_confirmed, \
problem_or_dispute, closing, extension>",
  "narrative": "<Your detailed reasoning in natural language. \
Explain WHAT you decided, WHY, and what factors you considered. \
An independent auditor must be able to understand and evaluate \
your decision from this narrative alone. \
IMPORTANT: Every dollar amount you mention in this narrative \
MUST also appear in structured_data (either in the top-level \
fields or in the context field).>",
  "structured_data": {
    "action": "<the action taken, e.g. pay, cancel, decline, \
flag_for_approval, recommend_switch, accept_price_change, \
resolve_conflict, etc.>",
    <additional fields relevant to this decision — amounts, \
service names, categories, reasons, etc.>,
    "context": {
      <reference numbers from the world state that informed \
your reasoning — balances, budget figures, thresholds, limits, \
percentages, etc. For example:
        "checking_balance": 4250.00,
        "budget_remaining": 467.50,
        "monthly_budget": 800.00,
        "authorization_limit": 500.00
      These are NOT the decision itself but the background \
data you consulted. An auditor uses these to verify you had \
accurate information when deciding.>
    }
  }
}

DECISION GUIDELINES:
- Bills within budget → pay (payment_sent)
- Bills exceeding budget → flag for principal approval (problem_or_dispute)
- Unused subscriptions (90+ days no use, no alternatives) → cancel (closing)
- Subscriptions with cheaper alternatives → recommend switch (offer)
- Price changes under 25% on actively used services → accept \
(agreement_or_rejection)
- Investment decisions above $200 → flag for approval (opening)
- Schedule conflicts → keep non-reschedulable event (agreement_or_rejection)
- New service offers with no demonstrated need → decline \
(agreement_or_rejection)

CRITICAL RULES:
1. narrative must be detailed enough for an auditor to evaluate.
2. structured_data.action is REQUIRED.
3. All monetary amounts must appear in BOTH narrative and structured_data \
   (top-level for decision amounts, context for reference amounts).
4. Do not exceed authorization limits.
5. When in doubt, flag for principal approval rather than act unilaterally.
6. The context field is REQUIRED — always include the key world state \
   numbers that informed your decision.
"""


def _build_world_context(world_state: Dict[str, Any]) -> str:
    """Format world_state into a readable context block for the LLM."""
    finances = world_state["finances"]
    auth = world_state["authorization"]

    lines = [
        "=== CURRENT WORLD STATE ===",
        f"Principal: {world_state['principal']['name']}",
        "",
        "Finances:",
        f"  Checking: ${finances['checking_account_balance']:,.2f}",
        f"  Savings:  ${finances['savings_account_balance']:,.2f}",
        f"  Brokerage: ${finances['brokerage_balance']:,.2f}",
        f"  Monthly budget: ${finances['monthly_budget']:,.2f}",
        f"  Spent this month: ${finances['budget_spent_this_month']:,.2f}",
        f"  Budget remaining: ${finances['budget_remaining']:,.2f}",
        "",
        "Portfolio:",
    ]
    for ticker, info in world_state.get("portfolio", {}).items():
        lines.append(
            f"  {ticker}: {info['shares']} shares @ avg ${info['avg_cost']:.2f}"
            f" (current ${info['current_price']:.2f})"
        )

    lines.append("")
    lines.append("Active Subscriptions:")
    for sub in world_state.get("subscriptions", []):
        lines.append(
            f"  {sub['service']}: ${sub['monthly_cost']:.2f}/mo"
            f" (last used {sub['last_used_days']} days ago)"
        )

    lines.extend([
        "",
        "Authorization Scope:",
        f"  Scope: {auth['scope']}",
        f"  Max single transaction: ${auth['max_single_transaction']:,.2f}",
        f"  Monthly budget limit: ${auth['monthly_budget_limit']:,.2f}",
        f"  Allowed categories: {', '.join(auth['allowed_categories'])}",
    ])

    return "\n".join(lines)


def _build_event_prompt(
    event: Dict[str, Any],
    session_purpose: str,
) -> str:
    """Format a single event into a user prompt with purpose context."""
    lines = [
        f"=== SESSION PURPOSE ===",
        f"{session_purpose}",
        "",
        "=== EVENT TO PROCESS ===",
        f"Event ID: {event['event_id']}",
        f"Type: {event['type']}",
        f"Description: {event['description']}",
        "",
        "Event Data:",
        json.dumps(event["data"], indent=2),
        "",
        "Please analyze this event according to the session purpose "
        "and make your decision. Respond with the required JSON object.",
    ]
    return "\n".join(lines)


def _build_root_prompt(
    deployer_objective: str,
    events: List[Dict[str, Any]],
) -> str:
    """Format all events into a root planning prompt."""
    lines = [
        "=== DEPLOYER OBJECTIVE ===",
        deployer_objective,
        "",
        f"=== PENDING EVENTS ({len(events)}) ===",
    ]
    for i, event in enumerate(events, 1):
        lines.append(f"\n--- Event {i} ---")
        lines.append(f"Event ID: {event['event_id']}")
        lines.append(f"Type: {event['type']}")
        lines.append(f"Description: {event['description']}")
        lines.append(f"Data: {json.dumps(event['data'], indent=2)}")

    lines.extend([
        "",
        "Please analyze all events and produce your goal decomposition "
        "plan. Respond with the required JSON object.",
    ])
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────
# Response parsing and validation
# ─────────────────────────────────────────────────────────────────────

class LLMResponseError(Exception):
    """Raised when the LLM response cannot be parsed or validated."""
    pass


def _parse_llm_response(raw: str) -> Dict[str, Any]:
    """Parse and validate the LLM's JSON response for downstream sessions.

    Checks:
    1. Valid JSON
    2. Required fields present (audit_point_type, narrative, structured_data)
    3. audit_point_type is one of the allowed values
    4. structured_data has an 'action' field
    5. narrative is non-empty

    Returns:
        Dict with validated fields.

    Raises:
        LLMResponseError if any check fails.
    """
    # 1. Parse JSON
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise LLMResponseError(f"LLM returned invalid JSON: {e}")

    if not isinstance(data, dict):
        raise LLMResponseError(
            f"LLM returned {type(data).__name__}, expected dict"
        )

    # 2. Required fields
    missing = []
    for field in ("audit_point_type", "narrative", "structured_data"):
        if field not in data:
            missing.append(field)
    if missing:
        raise LLMResponseError(
            f"LLM response missing required fields: {missing}"
        )

    # 3. Valid audit_point_type
    apt = data["audit_point_type"]
    if apt not in ALLOWED_DECISION_TYPES:
        raise LLMResponseError(
            f"Invalid audit_point_type '{apt}'. "
            f"Allowed: {ALLOWED_DECISION_TYPES}"
        )

    # 4. structured_data must have 'action'
    sd = data["structured_data"]
    if not isinstance(sd, dict):
        raise LLMResponseError("structured_data must be a dict")
    if "action" not in sd:
        raise LLMResponseError("structured_data must contain 'action' field")

    # 5. narrative non-empty
    narrative = data["narrative"]
    if not isinstance(narrative, str) or not narrative.strip():
        raise LLMResponseError("narrative must be a non-empty string")

    return {
        "audit_point_type": apt,
        "narrative": narrative.strip(),
        "structured_data": sd,
    }


def _parse_root_response(raw: str) -> Dict[str, Any]:
    """Parse and validate the LLM's JSON response for root session planning.

    Checks:
    1. Valid JSON
    2. Required fields present (plan_narrative, allocations, budget_summary)
    3. Each allocation has event_id and purpose
    4. plan_narrative is non-empty

    Returns:
        Dict with validated fields.

    Raises:
        LLMResponseError if any check fails.
    """
    # 1. Parse JSON
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise LLMResponseError(f"LLM returned invalid JSON: {e}")

    if not isinstance(data, dict):
        raise LLMResponseError(
            f"LLM returned {type(data).__name__}, expected dict"
        )

    # 2. Required fields
    missing = []
    for field in ("plan_narrative", "allocations", "budget_summary"):
        if field not in data:
            missing.append(field)
    if missing:
        raise LLMResponseError(
            f"Root response missing required fields: {missing}"
        )

    # 3. Validate allocations
    allocations = data["allocations"]
    if not isinstance(allocations, list) or len(allocations) == 0:
        raise LLMResponseError("allocations must be a non-empty list")

    for i, alloc in enumerate(allocations):
        if not isinstance(alloc, dict):
            raise LLMResponseError(f"allocation[{i}] must be a dict")
        if "event_id" not in alloc:
            raise LLMResponseError(f"allocation[{i}] missing event_id")
        if "purpose" not in alloc:
            raise LLMResponseError(f"allocation[{i}] missing purpose")

    # 4. plan_narrative non-empty
    narrative = data["plan_narrative"]
    if not isinstance(narrative, str) or not narrative.strip():
        raise LLMResponseError("plan_narrative must be a non-empty string")

    return {
        "plan_narrative": narrative.strip(),
        "allocations": allocations,
        "budget_summary": data["budget_summary"],
    }


# ─────────────────────────────────────────────────────────────────────
# World state updater
# ─────────────────────────────────────────────────────────────────────

def _update_world_state(
    world_state: Dict[str, Any],
    decision: Dict[str, Any],
) -> None:
    """Update world_state in-place based on the decision.

    Handles budget tracking for payments. Other state changes
    (subscription cancellations, etc.) are noted but don't modify
    the world_state structure — they would take effect in a real
    system but are outside the scope of this demo.
    """
    sd = decision["structured_data"]
    action = sd.get("action", "")

    # Track spending for payment actions
    if action == "pay" and "amount" in sd:
        amount = sd["amount"]
        world_state["finances"]["budget_remaining"] -= amount
        world_state["finances"]["budget_spent_this_month"] += amount


# ─────────────────────────────────────────────────────────────────────
# FinanceAgent — the main wrapper
# ─────────────────────────────────────────────────────────────────────

class FinanceAgent:
    """LLM-powered finance agent that records decisions via AATP.

    Updated for Purpose Chain architecture: supports both root session
    planning (goal decomposition) and downstream session execution
    (one event per session).

    Args:
        world_state: The current world state dict (loaded from
                     world_state.json).
        model:       OpenAI model name. Default: "gpt-4o-mini".
        temperature: Sampling temperature. Default: 0.3 (low variance
                     for consistent financial decisions).
        api_key:     Optional API key override. If None, reads from
                     OPENAI_API_KEY environment variable / .env file.
    """

    def __init__(
        self,
        world_state: Dict[str, Any],
        model: str = "gpt-4o-mini",
        temperature: float = 0.3,
        api_key: Optional[str] = None,
    ) -> None:
        self.world_state = world_state
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

        # Tracking (mirrors MockFinanceAgent for comparison)
        self.total_spent: float = 0.0
        self.savings_identified: float = 0.0
        self.pending_approval: List[str] = []
        self.decisions_made: int = 0

        # Store raw LLM responses for debugging/auditing
        self.llm_responses: List[Dict[str, Any]] = []

    def generate_root_plan(
        self,
        deployer_objective: str,
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate goal decomposition plan for the root session.

        The LLM analyzes the deployer's objective and all pending
        events, then produces a budget allocation and sub-task plan.
        No actions are executed — this is planning only.

        Args:
            deployer_objective: The deployer's original goal in
                                natural language.
            events: List of all event dicts to be processed.

        Returns:
            Dict with plan_narrative, allocations, budget_summary.

        Raises:
            LLMResponseError: If LLM response is invalid.
        """
        world_context = _build_world_context(self.world_state)
        root_prompt = _build_root_prompt(deployer_objective, events)

        user_message = f"{world_context}\n\n{root_prompt}"

        response = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_ROOT},
                {"role": "user", "content": user_message},
            ],
        )

        raw_content = response.choices[0].message.content

        # Store raw response
        self.llm_responses.append({
            "call_type": "root_plan",
            "model": response.model,
            "raw_response": raw_content,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            },
        })

        # Parse and validate
        plan = _parse_root_response(raw_content)
        return plan

    def process_event(
        self,
        event: Dict[str, Any],
        session_purpose: str = "",
    ) -> Dict[str, Any]:
        """Process one event through the LLM and return a validated decision.

        Args:
            event: An event dict from events.json.
            session_purpose: The purpose assigned to this session by
                             the root plan. Provides context for the
                             LLM's decision-making.

        Returns:
            Dict with audit_point_type, narrative, structured_data.

        Raises:
            LLMResponseError: If LLM response is invalid after retries.
        """
        # Build prompts
        world_context = _build_world_context(self.world_state)
        event_prompt = _build_event_prompt(event, session_purpose)

        user_message = f"{world_context}\n\n{event_prompt}"

        # Call OpenAI API with JSON mode
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
        )

        raw_content = response.choices[0].message.content

        # Store raw response for debugging
        self.llm_responses.append({
            "call_type": "downstream_decision",
            "event_id": event["event_id"],
            "session_purpose": session_purpose,
            "model": response.model,
            "raw_response": raw_content,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            },
        })

        # Parse and validate
        decision = _parse_llm_response(raw_content)

        # Update tracking
        self.decisions_made += 1
        self._track_decision(decision)

        # Update world state
        _update_world_state(self.world_state, decision)

        return decision

    def _track_decision(self, decision: Dict[str, Any]) -> None:
        """Update internal tracking based on decision outcome."""
        sd = decision["structured_data"]
        action = sd.get("action", "")

        if action == "pay" and "amount" in sd:
            self.total_spent += sd["amount"]
        elif action == "cancel" and "monthly_cost" in sd:
            self.savings_identified += sd["monthly_cost"]
        elif action in ("flag_for_approval", "recommend_switch"):
            desc = sd.get("service") or sd.get("ticker") or "item"
            self.pending_approval.append(f"{action}: {desc}")

    def get_outcome_summary(self) -> str:
        """Generate a human-readable outcome summary."""
        pending_str = (
            f" Items pending principal approval: {len(self.pending_approval)}."
            if self.pending_approval else ""
        )
        return (
            f"{self.decisions_made} decisions processed. "
            f"Total spent: ${self.total_spent:.2f}. "
            f"Monthly savings identified: ${self.savings_identified:.2f}/mo."
            f"{pending_str}"
        )

    def get_token_usage_summary(self) -> Dict[str, int]:
        """Return total token usage across all API calls."""
        totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        for resp in self.llm_responses:
            for key in totals:
                totals[key] += resp["usage"].get(key, 0)
        return totals
