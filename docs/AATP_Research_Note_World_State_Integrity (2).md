# AATP Research Note: World State Integrity Problem

**Date:** February 2026  
**Status:** Research — Pre-Design  
**Author:** Changxiao Huang (Norland)  
**Related:** Conceptual Framework v0.44 §4, §8; Execution Plan Stage 3+

---

## 1. Problem Statement

AATP currently audits agent **decisions** — the narrative, structured data, and hash chain ensure that what the agent *claims to have decided* is tamper-evident and reviewable. But there is an unaddressed asymmetry:

**The agent controls what context it includes in its audit records.**

An agent does not need to fabricate data to evade audit. It only needs to practice **selective narration** — recording facts that support its decision while omitting facts that would challenge it. For example:

- Agent decides to keep a subscription. Narrative states "user accessed service recently." Omits that usage dropped 90% over three months.
- Agent decides to buy a stock. Narrative cites positive analyst consensus. Omits that the stock already exceeded the portfolio's sector concentration limit.

In both cases, L1 (integrity) passes, L2 (conformance) passes, and L3 (reasonableness) is constrained to evaluating only what the agent chose to present. The audit trail is technically valid but epistemically incomplete.

**This is not a bug in AATP. It is an inherent limitation of any system where the recorder controls the evidence.**

---

## 2. Proposed Direction: World State Snapshots as Audit Evidence

The core idea: **anchor the agent's decision context into the audit chain, independent of the agent's narrative.**

At each decision point, a snapshot of the relevant world state is captured and sealed into the audit record alongside the agent's narrative and structured data. The auditor can then compare:

- What the agent **saw** (world state snapshot)
- What the agent **said** (narrative)
- What the agent **did** (structured data / action)

Discrepancies between the snapshot and the narrative become visible at L3 review.

---

## 3. Design Sketch

### 3.1 Snapshot Attachment (Minimal — No Protocol Change)

Use the existing `structured_data` field or EXTENSION records to embed a `world_state_snapshot` alongside each decision:

```json
{
  "audit_point_type": "PAYMENT",
  "narrative": "Paid electricity bill $127.50...",
  "structured_data": {
    "action": "pay",
    "amount": 127.50,
    "payee": "Electric Co",
    "__world_state_snapshot": {
      "bank_balance": 5200.00,
      "monthly_budget": 800.00,
      "spent_this_month": 340.00
    }
  }
}
```

**Pros:** Zero protocol change. Works today.  
**Cons:** Agent still controls what goes into the snapshot. No enforcement of completeness.

### 3.2 External World State Oracle (Medium — Application Layer)

Introduce a **World State Provider** — a component independent of the agent that captures and signs world state snapshots:

```
Event occurs
  → World State Provider captures full state, signs it
  → Agent receives (event + signed snapshot)
  → Agent makes decision, writes audit record
  → Audit record includes hash of the signed snapshot
  → Auditor can retrieve and verify the original snapshot
```

**Pros:** Agent cannot selectively omit context — the full snapshot exists independently.  
**Cons:** Requires a trusted external component. Adds infrastructure complexity.

### 3.3 World State Recording Standard (Long-term — Specification Layer)

Define a normative standard for world state recording:

- **Required fields per domain:** For financial agents, a snapshot MUST include: account balances, pending obligations, current holdings, budget status, relevant market data.
- **Completeness rules:** The snapshot must contain all data that the agent had access to at decision time, not a subset.
- **Signing:** Snapshots are signed by the data source (bank API, market feed, etc.) rather than by the agent.
- **Hash anchoring:** Each audit record references the snapshot hash. Auditor can request the full snapshot for verification.

This would be a separate specification (e.g., "AATP World State Profile for Financial Agents") layered on top of the core protocol.

### 3.4 Independent Witness LLM (Long-term — Architecture Extension)

Introduce a **third LLM role** dedicated to observing and recording world state, fully independent of the Agent and Auditor:

```
External event occurs
  → Witness LLM receives raw data (API responses, market feeds, notifications)
  → Witness records structured world state snapshot, signs with its own keys
  → Agent receives (event + Witness-signed snapshot)
  → Agent makes decision, writes audit record referencing Witness snapshot hash
  → Auditor reviews decision against both Agent narrative AND Witness record
```

This extends Invariant 6 (Agent/Auditor Independence) into a **three-role separation**:

| Role | Responsibility | Controls |
|------|---------------|----------|
| **Witness LLM** | Record what happened | Facts — the world state |
| **Agent LLM** | Decide what to do | Decisions — the actions |
| **Auditor LLM** | Evaluate the decision | Judgment — the review |

Each role has its own identity, its own signing keys, and its own chain. No single LLM controls both the evidence and the verdict.

**Cost mitigation strategies:**

- **Event-triggered only:** Witness activates when external events arrive, not continuously.
- **Batch mode:** Witness captures periodic snapshots (hourly/daily) rather than per-decision, with the snapshot hash covering a time window.
- **Tiered activation:** Low-value decisions use snapshot-in-structured-data (§3.1). High-value decisions (above a principal-defined threshold) trigger the full Witness pipeline.
- **Lightweight models:** Witness does not need advanced reasoning — it needs accurate structured extraction. A smaller, cheaper model (Haiku-class) may suffice.

**Philosophical note:** This mirrors real-world audit infrastructure. In accounting, transactions are recorded by bookkeepers (Witness), business decisions are made by management (Agent), and financial statements are reviewed by independent auditors (Auditor). The separation exists precisely because allowing the decision-maker to also control the evidence record creates an inherent conflict of interest.

**AATP compatibility:** This approach requires no changes to the core protocol. The Witness chain is simply another audit trail — it can use the same AuditRecord model, the same hash chain, the same verification tools. The linkage between Witness chain and Agent chain is established through cross-references (similar to bilateral mode's `counterparty_last_seq`).

---

## 4. Relationship to Current Architecture

| Approach | Protocol Impact | When |
|----------|----------------|------|
| 3.1 Snapshot in structured_data | None — fits current schema | Stage 3 (now) |
| 3.2 External Oracle | Application layer only | Post-Stage 4 |
| 3.3 Domain-specific Standard | New specification document | Community phase |
| 3.4 Independent Witness LLM | None — uses existing record model | Community phase |

**Invariant compliance:** All four approaches preserve the seven Core Invariants. The core protocol records decisions; world state integrity is an application-layer concern layered on top. The Witness LLM approach (§3.4) is a natural extension of Invariant 6's separation principle from two roles to three.

---

## 5. Stage 3 Recommendation

For the current Stage 3 implementation:

1. **In the Agent Wrapper's `build_prompt()` method**, include the full `world_state` and `event` as context to the LLM — this already happens by design.
2. **In the audit record's `structured_data`**, include a `context_snapshot` field containing the key world state values that were available to the agent at decision time.
3. **Do not enforce completeness yet** — this is a recording convenience, not a protocol requirement.
4. **In the Auditor LLM's prompt**, instruct it to compare the `context_snapshot` against the narrative for consistency and completeness.

This provides immediate auditability improvement with zero protocol changes, and establishes the data pattern for future formalization.

---

## 6. Open Questions

- **Snapshot granularity:** Full world state at every decision point is expensive. Differential snapshots (only changed fields) reduce size but complicate audit. What is the right balance?
- **Privacy:** World state may contain sensitive information (account numbers, holdings). Should snapshots be encrypted with auditor-only access?
- **Multi-source verification:** Can world state be independently verified against external sources (bank APIs, market feeds) to prevent both agent and oracle collusion?
- **Retroactive completeness:** If a new "required field" is added to a domain standard, how do we handle audit trails that pre-date the requirement?

---

## 7. Summary

The selective narration problem is real but bounded. AATP's existing architecture handles the most critical layer — ensuring that what is recorded cannot be tampered with. World state integrity adds the next layer — ensuring that what is recorded is a fair representation of reality.

The path forward is incremental: embed snapshots now (Stage 3), introduce independent capture later (post-Stage 4), and formalize domain standards when community adoption justifies it.

**The protocol records what happened. The snapshot records what the agent knew. Together, they enable genuine accountability.**

---

*AATP is designed to outlive its founder.*
