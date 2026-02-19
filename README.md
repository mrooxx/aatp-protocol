# AATP — Auditable Agent Transaction Protocol

**An open standard for recording and verifying AI agent decision-making.**

AI agents are sending emails, scheduling meetings, negotiating contracts, managing subscriptions, making purchases, and moving money on behalf of their owners — but none of them record *why* they made a particular decision. When your AI agent declines a meeting, accepts a contract term, or spends $65 on API credits, the current infrastructure can verify *what* happened but not *why* — and not whether you would have made the same choice.

Any decision an AI agent makes that affects the outside world — not just financial transactions — deserves the same accountability that human decisions receive. AATP provides that infrastructure. Economic decisions are the natural starting point because they are the easiest to quantify and audit, but the protocol's design applies wherever an AI agent exercises judgment on behalf of a human principal.

## Why Now

The infrastructure for autonomous AI agents is being deployed: communication protocols (Google A2A, Anthropic MCP), payment protocols (Coinbase x402, Google AP2), identity systems (W3C DIDs, Microsoft Entra Agent ID). What's missing is the accountability layer — a standard way to record and verify the decisions agents make on our behalf.

Recent independent research confirms the urgency. Google DeepMind's [Intelligent AI Delegation](https://arxiv.org/abs/2602.11865) framework (February 2026) argues for cryptographic accountability chains in agent delegation. Anthropic's engineering team documents the [compounding error problem](https://www.anthropic.com/engineering/multi-agent-research-system) in multi-agent systems and the need for [observability without content monitoring](https://www.anthropic.com/engineering/building-effective-agents). Multiple teams are converging on the same conclusion: **agent capability has outpaced agent accountability.**

AATP provides a concrete, implementable protocol — not just a theoretical framework.

## How It Works

AATP adds an **audit layer** alongside existing agent infrastructure. It does not replace any communication, payment, or identity protocol.

**Two layers:**
- **Working Channel** — where agents negotiate and transact (via A2A, MCP, etc.)
- **Audit Trail** — where decisions are recorded, sealed, and made reviewable

**Eight decision points** define when records are generated: Opening, Offer, Counter-Offer, Agreement/Rejection, Payment Sent, Payment Confirmed, Problem/Dispute, and Closing.

**Three operating modes** enable gradual adoption:

| Mode | Participants | Value |
|------|-------------|-------|
| **Solo** | 1 agent, no counterparty | Internal oversight of autonomous decisions |
| **Unilateral** | 1 AATP agent + 1 non-AATP agent | One-sided transaction audit |
| **Bilateral** | 2 AATP agents | Full cross-referenced accountability |

Solo mode means AATP is useful from day one — even a single personal AI managing subscriptions, filtering emails, or scheduling meetings benefits from auditable decision records.

## Core Design

Every audit record contains:

- **Narrative** — natural language explanation of what the agent decided and why (enables human judgment)
- **Structured data** — machine-readable fields for automated verification
- **Cryptographic seal** — SHA-256 hash + Ed25519 signature, chained to the previous record
- **Authorization reference** — link to the human principal's delegation scope

Three levels of review:

1. **Integrity** (automated) — hash chain valid? signatures valid? timestamps monotonic?
2. **Compliance** (semi-automated) — within authorization scope? narrative consistent with structured data?
3. **Reasonableness** (human/AI judgment) — did the agent pursue outcomes the principal would consider reasonable?

Level 3 is AATP's most distinctive contribution. It addresses the [boundary gap problem](docs/conceptual-framework-v0.44.md#15-foundational-premise-why-rules-alone-are-not-enough): when AI agents operate in spaces where no predefined rule applies, their judgment must still be auditable.

## Seven Invariants

These define what AATP *is*. Changing any invariant constitutes a new protocol, not an amendment.

1. **Dual-Layer Architecture** — working channel and audit trail are always separate
2. **Narrative + Structured Data Duality** — every record contains both; neither alone is sufficient
3. **Sealed Hash Chain** — records are immutable after creation and sequentially linked
4. **Decision-Point Model** — records at defined decision moments, not continuous streams
5. **Three-Level Review Separation** — integrity, compliance, and reasonableness remain distinct
6. **Agent and Auditor Independence** — the entity that creates records cannot review them
7. **Human Principal Sovereignty** — every audit trail traces back to a human principal

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    PRINCIPAL (Human Owner)            │
│         Sets authorization · Reads audit reports     │
└──────────────┬──────────────────────┬───────────────┘
               │                      │
               ▼                      ▼
┌──────────────────────┐  ┌──────────────────────────┐
│   MODULE 1: RECORDER │  │   MODULE 2: REVIEWER     │
│   (Accountant)       │  │   (Auditor)              │
│                      │  │                          │
│   • startSession()   │  │   • verifyChain()    L1  │
│   • recordDecision() │  │   • checkCompliance() L2 │
│   • endSession()     │  │   • getSessionForReview()│
│                      │  │   • submitReview()    L3 │
└──────────┬───────────┘  └──────────┬───────────────┘
           │     writes               │  reads
           ▼                          ▼
┌─────────────────────────────────────────────────────┐
│                 SEALED AUDIT TRAIL                    │
│   Record₁ ──hash──▶ Record₂ ──hash──▶ Record₃ ...   │
└─────────────────────────────────────────────────────┘
```

Detailed architecture diagrams are in [`diagrams/`](diagrams/).

## Project Status

**Phase: v0.x — Founder Stewardship**

| Component | Status |
|-----------|--------|
| Conceptual Framework (v0.44) | ✅ Complete |
| Governance Addendum (v0.21) | ✅ Complete |
| Architecture Diagrams | ✅ Complete |
| Technical Specification | 📝 In progress |
| Reference Implementation (Python SDK) | 🔨 In development |
| Solo Mode Demo | 🔜 Planned |
| Bilateral Mode Demo | 🔜 Planned |

See [ROADMAP.md](ROADMAP.md) for the development timeline.

## Quick Start

> Reference implementation is under active development. When ready:
> ```bash
> git clone https://github.com/mrooxx/aatp-protocol.git
> cd aatp-protocol
> pip install -e .
> python examples/demo_solo.py
> ```

## Documentation

- [**Conceptual Framework v0.44**](docs/conceptual-framework-v0.44.md) — full rationale, design principles, and protocol logic *(start here)*
- [**Governance Addendum v0.21**](docs/governance-v0.21.md) — versioning, invariant protection, transition plan
- [**Research: Audit-Derived Correction**](docs/research/audit-derived-correction.md) — how audit findings improve agent behavior

## Contributing

AATP is an open standard under active development. Contributions are welcome via [GitHub Issues](https://github.com/mrooxx/aatp-protocol/issues) and [Discussions](https://github.com/mrooxx/aatp-protocol/discussions).

During Phase I (Founder Stewardship, v0.x), the founding maintainer reviews all proposals. Phase II will transition to Working Group governance. See the [Governance Addendum](docs/governance-v0.21.md) for details.

## License

- **Documentation:** [CC BY 4.0](LICENSE-DOCS) — use, share, adapt with attribution
- **Code:** [MIT](LICENSE-CODE) — use freely

## Author

**Changxiao Huang (Norland)** — Accountant and protocol designer.

AATP grows from the conviction that AI decisions made on behalf of humans deserve accountability — whether those decisions involve money, communication, scheduling, or any other domain where an agent acts in the world. Economic transactions are the starting point because they are easiest to quantify; the principle extends to every decision an agent makes that its principal should be able to review.

GitHub: [@mrooxx](https://github.com/mrooxx)
