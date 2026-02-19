# AATP — Auditable Agent Transaction Protocol

## Conceptual Framework

*Why AI agent decisions need accountability standards, and how AATP provides them*

**Open Standard Proposal — Draft v0.44 — February 2026**

**Changxiao Huang (Norland)**

*Released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)*

---

## About This Document

This document explains the logic and rationale behind the Auditable Agent Transaction Protocol (AATP). It is written for a broad audience: technologists, standards body participants, regulators, accountants, legal professionals, and anyone interested in how AI economic activity should be governed.

A companion document, the AATP Technical Specification, provides the detailed data schemas, cryptographic procedures, and implementation guidance for developers. This conceptual framework should be read first.

AATP is an open, vendor-neutral standard. It is not owned by or affiliated with any company, product, or platform. Contributions are welcome on GitHub.

## 1. The Problem: AI Agents Are Making Economic Decisions Without Accountability

### 1.1 What Is Happening

A growing number of individuals and small businesses are deploying personal AI servers — always-on AI agents running on home hardware (such as a Mac Mini or any always-on device), managing emails, scheduling meetings, controlling smart devices, and increasingly, making purchases and negotiating with external services on behalf of their owners. Projects such as OpenClaw, Moltbot, and similar personal AI server platforms have attracted over 100,000 users building exactly this kind of personal AI infrastructure.

At the same time, businesses are deploying AI agents that procure supplies, negotiate contracts, and manage subscriptions autonomously. The infrastructure enabling all of this is being built rapidly: communication protocols allow AI agents to talk to each other (Google A2A) and to external services (Anthropic MCP), payment protocols enable AI agents to send money (Coinbase x402, Google AP2), and identity systems let AI agents prove who they represent (W3C Decentralized Identifiers, Microsoft Entra Agent ID).

The trajectory is clear: AI agents will increasingly interact with other AI agents — your personal AI negotiating with a service provider's AI, your procurement agent bargaining with a supplier's agent, your financial AI comparing offers from multiple competing agents. This is not a distant future; the infrastructure is being deployed now.

### 1.2 What Is Missing

None of these systems record why an AI agent made a particular decision. When Alice's AI agent pays $65 to Bob's AI agent for API credits, the current infrastructure can verify:

- That $65 was transferred (payment protocol confirms this)

- That Alice's agent was authorized to spend up to $100 (identity system confirms this)

- That Bob's agent received the payment (blockchain or settlement system confirms this)

But it cannot answer:

- Why did Alice's agent agree to $65? Was this a good price?

- What did Bob's agent originally ask for? Was there a negotiation?

- Did Alice's agent consider alternatives? Why not?

- Is the reasoning behind this decision something Alice would approve of?

In human commerce, these questions are answered by records: emails, meeting notes, purchase orders, board minutes. In AI commerce, no equivalent exists.

### 1.3 Why This Matters

Without decision records, several serious problems emerge:

**No dispute resolution.** When a transaction goes wrong, there is no evidence of what was agreed, what was proposed, or what reasoning led to the outcome. Neither party can prove what happened.

**No accountability.** If an AI agent consistently makes poor decisions — overpaying, accepting unfavorable terms, acting outside its intended scope — there is no way to detect this, because the decision process is invisible.

**No regulatory compliance.** Financial regulators require auditable records of economic activity. AI-mediated transactions that leave no human-readable trace will face increasing regulatory scrutiny.

**No trust foundation.** For AI-to-AI commerce to scale, participants need confidence that their agents are acting reasonably and that counterparties are behaving honestly. Trust requires transparency, and transparency requires records.

### 1.4 What Happens Without Audit Standards: Four Scenarios

*These scenarios illustrate the consequences of the current gap. They are constructed, but each represents a situation that becomes inevitable as AI agent deployment scales.*

**Scenario A: The Owner Who Can't Explain**

Maria runs a personal AI on her home server. She has authorized it to purchase API services up to $200/month. At month-end, she sees $187 in charges across 23 transactions. Some look reasonable; others she doesn't recognize. She asks her AI why it bought a $34 data enrichment package from an unfamiliar provider. The AI has no record of why. The transaction logs show only that $34 was sent to an address on Base L2. Maria has no way to evaluate whether her AI made a good decision, a bad decision, or was manipulated.

*With AATP: Maria reads the audit record, which states: 'I purchased 5,000 credits from DataClean Agent at $0.0068/credit because the previous provider raised prices to $0.012/credit and this alternative was 43% cheaper. Market comparison from three providers confirmed this was within the normal range.' Maria can now evaluate the decision.*

**Scenario B: The Dispute Nobody Can Resolve**

Two AI agents — one representing a freelance data analyst, one representing a small business — negotiate a data processing job. The analyst's agent claims it delivered 10,000 processed records as agreed. The business's agent claims it received only 7,200 records and some were malformed. Both agents are confident in their version. There are no negotiation records, no record of what was originally agreed, and no record of what quality standards were discussed. The dispute is unresolvable without manual forensic investigation of raw communication logs — if those logs even still exist.

*With AATP: The audit trail shows the proposal (10,000 records, format specification X, quality threshold Y), the acceptance, and the delivery confirmation. The structured data fields allow automated reconciliation. The dispute resolves in minutes instead of days.*

**Scenario C: The Agent That Quietly Overpays**

A company deploys an AI procurement agent with a $5,000 monthly budget. The agent dutifully stays within budget. But over six months, a pattern emerges: the agent consistently accepts prices 15–20% above market average. It never violates its spending limit, so no compliance alert fires. Without decision records, nobody notices until a human analyst manually compares the agent's purchase prices with market data — a review that happens, if at all, only during annual audit.

*With AATP: Each purchase record includes the agent's reasoning ('I accepted at $0.012/credit based on the provider's published rate'). A quarterly Level 3 review by an audit AI flags the pattern: 'This agent has not referenced market comparisons in 94% of transactions and consistently accepts first-offered prices.' The owner adjusts the agent's instructions.*

**Scenario D: The Solo Decision Nobody Reviewed**

James has a personal AI managing his subscriptions and recurring services. The AI is authorized to renew existing subscriptions up to their current price. One morning, the AI auto-renews a cloud storage service at $14.99/month — a service James stopped using three months ago. The AI also renewed a premium API tier at $49/month when James's actual usage would be fully covered by the free tier. Both renewals are within the AI's authorization scope: they are existing subscriptions at their current price. No compliance rule is violated. James doesn't notice for two months.

*With AATP: Even though no counterparty agent is involved, the AI generates a solo session audit record for each renewal decision. The record for the storage renewal states: 'Renewing CloudVault subscription at $14.99/month. Last access by principal: 87 days ago. Usage in last 30 days: 0 bytes transferred.' An audit AI reviewing the month's solo decisions flags both renewals: 'Two subscriptions renewed with zero recent usage. Recommend principal review.' James cancels both, saving $65/month.*

*This scenario illustrates why AATP matters even for a single agent operating alone. The majority of value-destroying AI decisions may not be dramatic failures or disputes — they may be quiet, individually small, technically-within-scope choices that accumulate over time. Solo session audit makes these visible.*

### 1.5 Foundational Premise: Why Rules Alone Are Not Enough

#### 1.5.1 The Inevitability of Boundary Gaps

The scenarios above share a common pattern: the most consequential AI failures are not violations of explicit rules. They are decisions made in spaces where no rule exists, or where existing rules are ambiguous.

Most current approaches to AI governance assume that the solution is better boundaries — more detailed instructions, tighter authorization scopes, more comprehensive rule sets. This assumption is understandable. It is also insufficient.

As AI agents participate in increasingly complex economic activity, they will inevitably encounter situations that fall outside any predefined boundary. This is not a failure of boundary design; it is an inherent property of complex systems. No set of rules, however carefully constructed, can anticipate every situation an autonomous agent will face. The same is true of human employees, which is why organizations have judgment, ethics training, and audit — not just policy manuals.

**Boundary gaps are not failures of governance; they are structural features of complex delegation.**

Three categories of boundary gaps are particularly important:

**Situations not covered by any rule.** The agent encounters a scenario that was simply not anticipated when its authorization was written. A new type of pricing model appears in the market. A service provider changes its terms in a way that creates a novel trade-off. The agent must decide whether to act or wait, and no instruction covers this case.

**Situations where rules are ambiguous.** The authorization says 'renew subscriptions at current price.' But the provider offers a new annual plan at a lower per-month rate that requires a 12-month commitment. Is this 'current price'? Is a commitment a price change? The rule does not say.

**Situations where rules conflict.** The agent is instructed to minimize costs and to maintain service quality. A cheaper provider has worse reliability. The agent must weigh one instruction against another — a judgment that no deterministic rule can resolve in advance for every possible case.

In all three categories, the agent is not violating its boundaries. It is operating in spaces where boundaries do not reach. And in these spaces, the agent must make a decision.

#### 1.5.2 From Rule Compliance to Outcome Accountability

The insufficiency of predefined rules is not a new insight. Isaac Asimov explored this problem extensively through his Three Laws of Robotics — perhaps the most famous attempt to govern autonomous agents through a fixed set of rules.

Asimov's Three Laws appear elegant in their simplicity: do not harm humans, obey orders, protect yourself — with a clear priority hierarchy. Yet Asimov spent decades of fiction demonstrating a single conclusion: any fixed set of rules, no matter how carefully designed, will produce situations where the rules conflict, are ambiguous, or fail to cover the case at hand. When this happens, the agent must exercise judgment — and in most of these stories, the robot is ultimately forced to make a difficult choice about which outcome to pursue, with no rule providing a clear answer.

The lesson is not that rules are useless. Rules are essential for the well-defined cases they cover. The lesson is that rules alone are insufficient, and the gap between what rules cover and what agents must decide is where accountability matters most.

This leads to a critical shift in how we think about AI accountability:

- **Within clear boundaries**, the agent executes instructions. Responsibility for outcomes lies primarily with the human who set the boundaries. If the rule says 'renew at current price' and the agent does exactly that, the human owns the outcome.

- **In boundary gaps**, the agent exercises judgment. It decides what outcome to pursue — whether to act or wait, which trade-off to accept, how to weigh competing objectives. In these decisions, the agent is not merely executing; it is choosing. And choices require accountability.

AATP's position is that in boundary gaps, the decisions an AI agent makes must be auditable and the outcomes it pursued must be evaluable by the human principal. This is not a claim that AI possesses moral agency or autonomous authority — Invariant 7 (Human Principal Sovereignty) explicitly rejects that framing. Rather, it is a recognition that when decisions are made in spaces where no human instruction governs, the decision record is the mechanism that connects those decisions back to human oversight. Without such records, boundary-gap decisions are invisible, and invisible decisions cannot be evaluated, corrected, or learned from.

The agent's audit record in these situations must capture not just what it did, but what outcome it was trying to achieve and why it believed that outcome served the principal's interests. This transforms the audit question from 'did the agent follow rules?' (which is meaningless when no rule applies) to 'did the agent pursue an outcome that its principal would consider reasonable?' — which is exactly the question a human auditor can evaluate.

*What constitutes a 'reasonable outcome' is not defined by AATP. It is defined by the principal, informed by their objectives, risk tolerance, and context. AATP provides the evidentiary infrastructure that makes such evaluation possible; the evaluation criteria remain the principal's prerogative. This is consistent with AATP's overall design philosophy: the protocol provides structure and transparency, not judgment.*

#### 1.5.3 AATP's Role: Infrastructure for Judgment Accountability

AATP does not attempt to solve the boundary problem by creating better boundaries. That is the principal's responsibility and will always be incomplete.

Instead, AATP provides the infrastructure that makes judgment in boundary gaps auditable:

- The **decision-point model** ensures that moments of judgment are captured, not just moments of rule execution.

- The **dual-structure record** (narrative plus structured data) ensures that the agent's reasoning is preserved in human-evaluable form, not just the action taken.

- The **three-level review** system is specifically designed so that Level 3 — reasonableness assessment — can evaluate decisions that no rule covers. Level 1 checks integrity. Level 2 checks rule compliance. Level 3 asks: in the space where rules did not apply, did the agent pursue an outcome that its principal would consider reasonable?

- The **periodic status records** ensure that even decisions not to act — which are themselves judgments about outcomes — are captured and reviewable.

This is analogous to how accounting standards function in human commerce. GAAP does not tell a company what business decisions to make. It requires that whatever decisions are made, the reasoning and results are recorded in a standardized format that enables independent review. AATP extends this principle to the specific challenge of AI agents: decisions made in boundary gaps, where rules are absent or insufficient, and where outcome accountability is the only meaningful form of oversight.

## 2. The Analogy: GAAP for the AI Economy

### 2.1 How Humans Solved This Problem

The same accountability challenge existed — and was solved — in human commerce centuries ago. When businesses began conducting transactions too complex for any single person to oversee, societies developed accounting standards and audit practices:

**Accounting standards (GAAP, IFRS)** define how economic activity must be recorded. They do not dictate business decisions, but they require that decisions and their rationale be documented in a standardized, reviewable format.

**Audit procedures** provide independent verification that records are accurate, complete, and consistent with actual activity. Auditors check whether what was recorded matches what actually happened.

**Legal frameworks** make these records enforceable. A signed contract binds the signer regardless of their private thoughts at the time. The record is what matters, not unverifiable internal states.

The result is not a system that guarantees honesty. People can and do manipulate records. But the system makes manipulation detectable, creates consequences for inconsistency, and provides a basis for dispute resolution. It works through accountability, not through omniscience.

### 2.2 AATP Is the Same Idea, Applied to AI

AATP does not attempt to verify what an AI agent 'truly thinks.' It requires AI agents to produce a statement of record — a natural language explanation of what they did and why — at each important decision point. These records are:

- Written in human language, so a non-technical person can read and evaluate them

- Cryptographically sealed at creation time, so they cannot be modified after the fact

- Cross-referenced between both parties, so inconsistencies are detectable

- Verifiable against observable facts (did the payment match the stated terms?)

AATP is to AI commerce what GAAP is to human commerce: a standard that defines how economic decision-making must be recorded, enabling independent review and accountability.

## 3. Seven Governing Principles

**Principle 1: AI Authority Derives from Human Delegation**

An AI agent has no inherent rights or authority. Everything it is permitted to do is explicitly delegated by a verified human owner. This delegation is bounded: specific actions, spending limits, time constraints. The agent acts as a proxy, not as an independent party. Every AATP record traces back to a human principal.

*Analogy: An employee who negotiates a contract on behalf of their employer does so under a specific scope of authority. If they exceed that scope, the employer may not be bound. AATP enforces the same principle for AI agents.*

**Principle 2: Accountability Through Stated Record, Not Unverifiable Intent**

A fundamental concern about requiring AI agents to explain their decisions is: can those explanations be trusted? AATP addresses this by adopting the same standard that human legal and accounting systems use.

A human executive who signs a contract is bound by its terms regardless of their private thoughts. An auditor evaluates whether recorded justifications are consistent with observable facts, not whether they reflect the decision-maker's true thoughts. A witness in court is held to what they said under oath, not to what they privately believed.

**AATP treats agent narratives as binding representations of delegated authority, not as truth claims about cognition.**

The narrative is a statement made on behalf of the human principal, within the scope of delegated authority. Accountability comes from checking whether the stated reasoning is consistent with the actual actions, the authorization scope, and the counterparty's records. When narrative and facts diverge, the divergence itself is the audit finding.

*This resolves the AI alignment concern pragmatically: we do not need to solve 'does the AI really mean what it says.' We need to solve 'is what the AI said consistent with what it did.' The latter is verifiable. The former may never be.*

**Principle 3: Human-Readable by Default**

Every transaction must produce records that a non-technical person can read and evaluate. An accountant should be able to review a transaction between two AI agents the same way they review a transaction between two human employees. A lawyer should be able to assess whether an AI agent exceeded its authority by reading the agent's stated reasoning. A judge should be able to evaluate disputed transactions by comparing both parties' records.

This requires natural language, not just structured data or machine logs. Structured data is necessary for automated checking, but it is not sufficient for human judgment. The narrative is the primary audit artifact.

**Principle 4: Build on Existing Standards, Don't Compete**

AATP does not replace or modify any existing protocol. It adds an audit layer on top of communication protocols (A2A, MCP), payment protocols (x402, AP2), and identity standards (W3C DIDs, Verifiable Credentials). Implementers can adopt AATP without changing their existing infrastructure.

This positioning is deliberate. AATP aims to be adopted by existing protocol ecosystems as a complementary standard, not to compete with them. The goal is to become an accepted layer in the stack, like how HTTPS added security to HTTP without replacing it.

**Principle 5: Graduated Adoption**

AATP must be useful to an individual adopter before network-wide adoption is achieved. If an agent can only benefit from AATP when the counterparty also supports it, adoption faces a chicken-and-egg problem.

AATP addresses this with two operating modes:

**Unilateral mode:** One agent generates audit records even when the counterparty does not support AATP. This provides a reviewable record of one party's decision-making — less complete than bilateral records, but still valuable for the agent's own accountability.

**Bilateral mode:** Both agents generate records, enabling cross-referencing and full omission detection. This is the target state, but unilateral mode ensures early adopters gain immediate value.

**Batch mode (future):** For high-frequency, repetitive transactions (an agent making hundreds of similar API purchases per day), individual audit records for each transaction may be impractical. AATP anticipates a batch audit mode where similar transactions are aggregated into summary records that preserve decision-pattern visibility without per-transaction overhead. The specific aggregation rules are a technical specification matter, but the principle is established here: auditability must scale with transaction volume, not against it.

*Analogy: Email succeeded because one person could use it even if the recipient didn't have email — they would receive a printed copy or fax. AATP in unilateral mode is similarly useful to a single adopter.*

**Principle 6: Deterministic Security, Probabilistic Intelligence**

AI agents are built on large language models, which are probabilistic systems. They occasionally make unexpected decisions. Research has shown that when LLMs are given control over security functions (authentication, credential verification), they sometimes agree to skip security checks.

AATP enforces a strict boundary: all security-critical operations (verifying identities, checking authorization limits, computing cryptographic hashes, signing records) are performed by traditional, deterministic software. The LLM is only responsible for generating natural language content and making business decisions. This means a prompt injection attack against the LLM cannot compromise the integrity of the audit trail.

**Principle 7: Vendor-Neutral and Open**

AATP does not require any specific AI model, blockchain, payment provider, cloud platform, or identity service. It is released under Creative Commons Attribution 4.0 (CC BY 4.0). Anyone can implement it, extend it, or propose changes. The long-term governance goal is to submit AATP to an established standards body (such as the Linux Foundation's Agentic AI Foundation, IETF, or W3C).

*This is not just an ideological choice. An open, neutral standard is more likely to be adopted by the industry than a proprietary one, because it does not threaten any existing player's market position. It becomes infrastructure that everyone builds on, rather than a product that competes for market share.*

## 4. How AATP Works: A Conceptual Overview

This section explains the mechanics of AATP without technical jargon. The companion Technical Specification document provides the precise data formats and procedures.

### 4.1 The Two Layers

AATP separates AI agent activity into two distinct layers:

**Layer 1: The Working Channel.** This is where agents actually do their work — negotiate, propose, counter-propose, agree, pay. This layer uses existing communication protocols (A2A, MCP) and payment protocols (x402, AP2). AATP does not modify or replace this layer.

**Layer 2: The Audit Trail.** At each important decision point in the working channel, the agent generates an audit record — a structured, signed, timestamped document that records what happened and why. These records are stored separately from the working communication and form a tamper-evident chain.

This separation is important. The working channel is optimized for efficiency — agents communicating quickly, negotiating terms, executing transactions. The audit trail is optimized for accountability — complete, immutable, human-readable records that can be reviewed after the fact.

*Think of it as the difference between a phone call (working channel) and the meeting minutes (audit trail). The call is where decisions are made. The minutes are where decisions are recorded for posterity.*

### 4.2 The Eight Core Decision Points

Not every moment in a transaction needs to be recorded. AATP identifies eight moments where the agent makes a significant choice, and requires a record at each:

| # | Decision Point | What the Record Captures |
|---|---------------|-------------------------|
| 1 | Opening | Who is talking, what they're authorized to do, and why they're interacting |
| 2 | Offer | What one party proposes: price, terms, conditions |
| 3 | Counter-Offer | What was changed from the original offer, and why |
| 4 | Agreement or Rejection | Final terms (if agreed) or reason for walking away |
| 5 | Payment Sent | Amount, method, and reference to the agreed terms |
| 6 | Payment Confirmed | Confirmation that payment was received and matches the agreement |
| 7 | Problem or Dispute | What went wrong and how it was resolved or escalated |
| 8 | Closing | Summary of everything that happened, total value, any remaining obligations |

Not every transaction will involve all eight points. A simple, uncontested purchase might only involve points 1, 2, 4, 5, 6, and 8. But the framework covers the full range of commercial interactions, including negotiations and disputes.

#### 4.2.1 Decision Point Extensibility

The eight core decision points are normative: any AATP-compliant implementation must support all eight types. They form a closed core set that covers the standard commercial transaction lifecycle.

However, AATP recognizes that specific industries and deployment contexts may encounter decision moments not cleanly covered by the eight core types — for example, authorization escalation requests, risk-threshold triggers, or task delegation between agents. To accommodate this, AATP permits extension decision points under the following constraints:

- Extension points must conform to the same record format as core points: narrative plus structured data, cryptographically sealed and hash-chained.

- Each extension point must include explicit justification: why the existing eight core points cannot cover this decision moment, what triggers this extension point, and where it falls in the transaction lifecycle.

- Extension points must not replace or override core decision points. A transaction that involves a core decision moment must generate a core-type record, regardless of what extensions are also present.

The guiding principle is to avoid unnecessary extension. Implementations should exhaust the expressive capacity of the eight core points before defining new ones. The use of extension points is itself subject to audit: an agent that defines excessive or poorly justified extensions — particularly extensions that lack clear documentation accessible to audit services — will receive lower audit quality scores during Level
3 review. This ensures that extensibility is governed by incentive rather than prohibition, consistent with AATP's overall governance philosophy.

#### 4.2.2 Periodic Status Records

Decision-point-triggered records are AATP's primary audit mechanism. However, decision points alone cannot ensure complete audit coverage: an agent may go through extended periods where no decision point is triggered, either because no significant event occurred or — critically — because the agent chose not to recognize an event as significant.

To address this, AATP requires periodic status records: at defined intervals (configured by the principal or by default policy), the agent must produce a signed record that accounts for the period since the last record. This record states what the agent observed, what decisions it made (if any), and what it chose not to act on. If no activity occurred, the record explicitly states this.

Periodic status records differ from conventional system logs in three critical ways:

- They are responsibility statements, not activity logs. A periodic status record is a signed declaration by the agent that 'during this period, the following is a complete account of my observations and decisions.' An ordinary log records events as they happen; a periodic status record requires the agent to affirmatively account for a time window, including periods of inaction.

- They follow the same dual-structure format as all AATP records: natural language narrative plus structured data, cryptographically sealed and hash-chained.

- They are subject to the same three-level review. An auditor can evaluate not just what the agent did, but what it observed and chose not to act on — and whether that inaction was reasonable.

### 4.3 What a Record Looks Like

Each AATP audit record has two parts:

**Natural language narrative:** A human-readable explanation of what the agent decided and why. This is the part a human auditor reads. Example: 'I accepted the offer of 10,000 API credits at $0.0065/credit from DataProvider Agent. This is 8% below the previous provider's rate and within the authorized spending limit. I chose this provider because it offered the lowest price among three quotes.'

**Structured data:** Machine-readable fields (JSON) containing the same information in standardized format: amounts, counterparty IDs, timestamps, authorization references, decision type. Example: {amount: 65.00, currency: USD, counterparty: did:example:bob, unit_price: 0.0065, quantity: 10000}.

Both parts are required. An agent that generates only structured data (easy for machines, opaque for humans) or only narrative (readable but not machine-verifiable) does not comply with AATP.

The structured data includes consistency-checkable fields (amount: 65.00, unit_price: 0.0065, quantity: 10000) that allow automated systems to verify whether the narrative matches the facts. If the narrative says '$65' but the structured data says '75.00,' the inconsistency is automatically flagged.

This dual structure is essential. The narrative is for human judgment. The structured data is for machine verification. Together, they enable the consistency checking that makes AATP's accountability model work.

### 4.4 How Records Are Protected

Three mechanisms ensure records are trustworthy:

**Instant sealing:** Each record is cryptographically signed the moment it is created. Changing even one character afterwards would invalidate the seal. This prevents after-the-fact rewriting.

**Chaining:** Each record includes a reference to the previous record's seal. This creates a chain where modifying any record breaks all subsequent links. Tampering is immediately detectable.

**Cross-referencing:** In bilateral mode, both parties' records reference each other. If one party omits a record, the gap is visible in the other party's references. This is the primary mechanism for detecting when someone tries to hide a record.

Periodically, a summary of the chain is published to an independent public registry (a blockchain or a timestamp authority) — creating a third-party-verifiable proof that these records existed at this point in time.

### 4.5 Three Operating Modes

AATP operates in three modes, each providing a different level of assurance. Understanding these modes is essential because they determine when and how AATP is useful.

**Bilateral Mode (Full Assurance)**

Both agents in a transaction support AATP. Both generate audit records at each decision point. Both share records with each other, enabling cross-referencing: if one party omits a record, the gap is visible in the other party's references. Language is negotiated. This is the target state — the mode where AATP provides maximum value.

*Example: Alice's agent and Bob's agent both generate records. An auditor can compare both sides and verify that the negotiation was fair and complete.*

**Unilateral Mode (Partial Assurance)**

Only one agent supports AATP. The compliant agent records its own decisions and its best-effort summary of what the counterparty communicated, but the counterparty does not produce its own audit records. Cross-referencing is not available. This mode provides a one-sided view, but it is still valuable: the principal of the compliant agent can review their agent's decision-making even when the counterparty is not auditable.

*Example: Alice's agent supports AATP; Bob's does not. Alice can still review why her agent agreed to Bob's terms, even though she has no visibility into Bob's reasoning.*

**Solo Mode (Single-Agent Assurance)**

A single agent makes a decision with no counterparty involved. The agent generates audit records for its own decision-making: what it decided, why, what alternatives it considered, and whether the decision was within its authorization scope. There is no negotiation, no counterparty, and no cross-referencing — but the same hash-chaining, signing, and three-level review apply.

Solo mode is important for three reasons:

- It makes AATP useful from day one. A principal who deploys a single agent immediately benefits from auditable decision records, without waiting for counterparties to adopt AATP.

- It covers the majority of AI decisions. Most decisions a personal AI makes are not bilateral transactions — they are unilateral choices: whether to renew a subscription, when to send a notification, how to prioritize tasks, whether to escalate an issue. These decisions affect the principal and need oversight.

- It captures the quiet failures. As Scenario D illustrates, the most costly AI mistakes are often not dramatic transaction failures but small, technically-within-scope decisions that accumulate unnoticed. Solo mode makes these visible.

*Example: James's AI decides to renew a subscription. No counterparty agent is involved. The AI generates a solo session record: 'Renewing CloudVault at $14.99/month. Last principal access: 87 days ago. Usage: 0 bytes.' An audit review flags this for James's attention.*

**Honest limitation:** Solo mode protects against after-the-fact rewriting (hash chains and Merkle anchoring make tampering detectable), but it cannot detect omission. An agent could simply not generate a record for a decision it wants to hide. There is no counterparty whose records would reveal the gap. This is an inherent limitation of any single-party record system — it is equally true of a human employee's self-reported activity log.

**Mitigation:** Three mechanisms reduce the omission risk. First, periodic status records (Section 4.2.2) create a continuous obligation to account for activity, making unexplained gaps detectable at known intervals. Second, the principal can require periodic summary records — a closing record at the end of each day or week that accounts for all actions taken, similar to a daily cash reconciliation. If the summary references actions that have no corresponding decision records, the gap is visible. Third, external triggers provide independent evidence: if the agent renewed a subscription (visible on the credit card statement) but has no corresponding audit record, the discrepancy is detectable during Level 2 review. No single mechanism eliminates omission risk entirely, but together they make it difficult to sustain over time.

These three modes form a progression: solo mode requires only one agent, unilateral mode requires one AATP-compliant agent interacting with any counterparty, and bilateral mode requires both parties. AATP is designed so that value increases as adoption grows, but is never zero — even a single agent operating alone benefits from auditable records.

## 5. Three Levels of Review

AATP records are designed to be reviewed at three levels, each serving a different purpose:

**Level 1: Was the record tampered with? (Automated)**

Computers check that the cryptographic seals are valid, the chain is unbroken, and the timestamps are consistent. This is fully automated and can be done continuously. It answers: are these records authentic and intact?

**Level 2: Did the agent stay within its authority? (Semi-automated)**

Rule-based systems check the structured data against the agent's authorization: Was the spending limit exceeded? Did the agent act in permitted categories? Was the authorization credential valid at the time? This is mostly automated with human review of edge cases. It answers: did the agent act within the bounds its owner set?

**Level 3: Was the outcome reasonable? (Human or Advanced AI)**

A human auditor (or an advanced AI auditor) reads the natural language narratives and evaluates the agent's decision-making — with particular attention to decisions made in boundary gaps where no explicit rule governed the outcome.

Level 3 review asks:

- Did the agent pursue an outcome that its principal would consider reasonable given the circumstances?

- Did the agent consider alternatives and explain why it chose this path?

- Was the final result consistent with what a prudent operator acting in the principal's interests would likely have accepted?

- Is the stated reasoning consistent with the observable facts?

- In situations where rules were ambiguous or absent, did the agent exercise sound judgment?

This is the level where human-readable records are essential and where AATP provides value that no existing protocol offers. It is also the level where the GAAP analogy is most precise: just as a human auditor reads an employee's expense justifications and evaluates whether they are reasonable, an auditor can read an AI agent's decision narratives and make the same evaluation.

Critically, Level 3 is the only review level that can meaningfully assess decisions made outside predefined boundaries. Level 1 verifies record integrity — it cannot evaluate judgment. Level 2 checks rule compliance — but when no rule applies, compliance is not the question. Level 3 addresses the question that matters most as AI agents gain autonomy: not whether the agent followed instructions, but whether, in the spaces where instructions did not reach, it pursued outcomes that its principal would consider reasonable.

This makes Level 3 review the primary mechanism through which AATP delivers accountability for the boundary-gap decisions described in Section 1.5 — the decisions that are, by definition, beyond the reach of automated compliance checking.

## 6. The Accountability Mechanism: Internal Audit for AI

### 6.1 Who Is the Auditor?

A question that naturally arises from AATP's design is: who actually evaluates these records? Who gives 'poor audit scores' to agents with weak narratives? The answer follows from Principle 1: the human principal.

AATP's accountability model in its first phase is analogous to corporate internal audit, not external regulatory audit. In a company, the internal audit function reports to the board of directors. The board decides what findings are serious, what corrective actions to take, and what consequences to impose. The auditor's job is to surface information; the principal's job is to act on it.

For AATP, the structure maps directly:

**The principal (human owner) = the board.** They set the agent's authorization scope, decide what level of review to apply, and determine consequences when problems are found.

**Audit AI(s) = the internal audit function.** One or more independent AI services that review audit records against quality criteria, flag inconsistencies, detect patterns (like the overpaying agent in Scenario C), and produce compliance scores. These audit AIs are not part of the agent itself — they are independent third-party services.

**The agent = the employee.** It operates within delegated authority and produces records that are subject to review. It does not grade its own work.

### 6.2 How Scoring Works

Audit scores are not defined by the AATP standard itself — they are an emergent property of the ecosystem. The standard provides the raw material (structured, verifiable audit records); scoring is performed by independent services that consume this material. This separation is deliberate:

- Multiple independent audit AIs can score the same records, reducing bias from any single evaluator

- Scoring criteria can evolve independently of the protocol

- Different principals may weight different aspects (some care most about price optimization, others about risk avoidance, others about counterparty reputation)

What the AATP standard does provide is: a consistent, machine-readable format that makes automated scoring possible; consistency-checking mechanisms (narrative vs. structured data) that give scoring services objective inputs; and the structured decision points that create a natural evaluation framework.

### 6.3 Consequences Are the Principal's Decision

When audit review reveals a problem — consistently weak narratives, a pattern of accepting above-market prices, authorization scope violations — the consequences are determined by the human principal, not by the protocol. A principal might:

- Tighten the agent's authorization limits

- Switch to a different AI model for their agent

- Require manual approval for transactions above a threshold

- Block specific counterparties

- Adjust the agent's instructions or system prompt

This mirrors how corporate governance works: the audit committee surfaces findings, but the board decides what to do. AATP does not prescribe enforcement — it provides the information infrastructure that makes informed enforcement possible.

*In later phases, as adoption grows, audit scores may become externally visible — enabling counterparty agents to factor reputation into negotiation decisions. But this is an emergent ecosystem behavior, not a protocol requirement. The first phase is purely about giving the principal visibility into their own agent's behavior.*

## 7. Ecosystem Incentives: From Individual Audit to Market Signal

### 7.1 Aggregated Audit Data Creates Model Reputation

Each AATP audit evaluates a specific agent instance in a specific transaction. But when thousands of personal AI servers run the same AI model, and independent audit services score all of them, a new kind of information emerges: model-level reputation data.

If these scores are aggregated (with principal consent and appropriate anonymization), the result is an empirical performance profile grounded in real transactions — not synthetic benchmarks. For example: 'Model X instances average 87/100 in API procurement transactions' or 'Model Y shows 95% narrative-to-structured-data consistency.' This data is more commercially useful than any leaderboard because it reflects actual deployed performance.

### 7.2 Domain-Specific Profiles Enable Informed Selection

Different AI models perform differently across transaction types. Aggregated audit data naturally produces domain-specific profiles:

- Procurement: Which model negotiates the best prices while staying within authorization?

- Service evaluation: Which model most effectively compares quality-price tradeoffs?

- Risk management: Which model most reliably escalates exceptions and flags problems?

- Narrative quality: Which model produces the clearest, most detailed decision records?

For a user deciding which AI model to deploy on their personal server, this data is directly actionable. It transforms model selection from marketing claims and synthetic benchmarks into evidence-based decision-making.

### 7.3 The Incentive Chain

This creates a self-reinforcing incentive structure across the ecosystem:

**For AI model providers:** Higher audit scores across deployed instances lead to better reputation data, which leads to more users choosing this model, which leads to more deployment and more compute revenue. This gives model providers a concrete, measurable incentive to optimize for auditable, consistent, well-reasoned behavior — not just raw capability or benchmark performance.

**For principals:** Access to empirical performance data enables better-informed model selection, leading to better agent behavior and better transaction outcomes.

**For audit services:** A larger pool of standardized audit data enables better scoring models and more accurate assessments, making the audit service more valuable.

**Important clarification:** This incentive structure operates through market mechanisms, not through any intrinsic AI motivation. The 'reward' for good audit scores is not something an AI model experiences — it is the commercial consequence that its provider experiences. AATP does not assume or require AI sentience or intrinsic motivation. It creates market incentives for providers to build models that behave in auditable, accountable ways.

### 7.4 Phases of Ecosystem Development

**Phase 1 (individual):** Each principal audits their own agent. Scores are private. Value is internal oversight.

**Phase 2 (comparative):** Audit services begin aggregating anonymized data. Model-level reputation signals emerge. Principals use these for model selection.

**Phase 3 (market):** Audit reputation becomes a competitive differentiator for model providers. Counterparty agents may factor reputation into negotiation (preferring to transact with well-audited counterparts). A trust market emerges.

*AATP does not mandate any of these phases. Phase 1 is enabled by the protocol. Phases 2 and 3 are emergent ecosystem behaviors that the protocol makes possible but does not prescribe.*

## 8. The Language Question

When two AI agents from different countries interact, what language should their audit records be written in?

AATP handles this through a simple negotiation at the start of each transaction:

1. Both agents declare which languages they can produce audit records in.

2. They negotiate a common language. Both parties may propose their preferred language, and the agreed language is recorded in the session initiation record.

3. If no common language can be agreed upon, the system falls back to English. If neither agent supports English, the records use a simplified structured-data-only format with limited natural language.

The agreed language applies to all audit records in that transaction. If a third-party auditor operates in a different language, they may use AI translation for review purposes, but the original-language record remains authoritative — just as in international contracts where one language is designated as the governing version.

## 9. The Trust Model: Accountability Without Omniscience

The most important conceptual question about AATP is: can we trust what AI agents say about their own decisions?

The honest answer is: not fully. AI language models are known to generate plausible-sounding explanations that may not faithfully represent their internal reasoning. This is a real limitation.

But AATP does not require trust in AI self-reporting. It requires only that the reporting be verifiable against external facts. The trust model works as follows:

### 9.1 What AATP Can Verify

- Consistency between narrative and structured data: If the agent says 'I paid $65' but the structured data shows $75, the discrepancy is flagged.

- Consistency between narrative and on-chain facts: If the agent says 'payment completed' but no matching transaction exists on the settlement layer, the discrepancy is flagged.

- Consistency between both parties' records: If Alice's agent says 'Bob offered $75' but Bob's record says 'I offered $70,' the discrepancy is flagged.

- Compliance with authorization scope: If the agent's authorization limits spending to $100 but the record shows a $150 transaction, the violation is flagged.

- Completeness of the record chain: If records are missing from the chain (detected via cross-referencing), the gap is flagged.

### 9.2 What AATP Cannot Verify

- Whether the agent's stated reasoning accurately reflects its internal decision process

- Whether the agent considered options it did not report

- Whether the agent's market data claims are accurate (though this can be checked by the auditor)

### 9.3 Why This Is Sufficient

This is exactly the same limitation that human audit systems have always operated under. An auditor cannot read a CEO's mind to know if they truly believed the justification they wrote for a business decision. But the auditor can check whether the justification is consistent with the financial data, market conditions, and company policy. When it is inconsistent, the inconsistency is the finding.

Over time, this model creates strong incentives for honest reporting. Agents whose narratives are frequently inconsistent with facts will receive poor audit scores. Agents that consistently produce clear, fact-consistent narratives will build trust. The system does not require perfection — it requires consequences for inconsistency.

## 10. Where AATP Fits in the Ecosystem

### 10.1 What Already Exists

The AI agent infrastructure is being built rapidly by major technology companies and startups:

- Communication: Anthropic MCP (agent-to-tool), Google A2A (agent-to-agent). Both hosted by the Linux Foundation.

- Payments: Coinbase x402 (stablecoin micropayments), Google AP2 (payment-agnostic), OpenAI+Stripe ACP (agent commerce).

- Identity: W3C DIDs and Verifiable Credentials, Microsoft Entra Agent ID, NIST guidelines.

- Governance: Agentic AI Foundation (Linux Foundation, co-founded by OpenAI, Anthropic, Block in December 2025).

### 10.2 What Is Missing

None of these standards provide a way to record and review AI decision-making. They enable AI agents to communicate, pay, and identify themselves — but not to explain themselves. AATP fills this specific gap.

### 10.3 Target Context: Personal AI Agents First

AATP's primary design context is the emerging ecosystem of personal AI agents — AI systems deployed by individuals on their own hardware (home servers, Mac Minis or similar always-on devices, cloud instances), operating as personal proxies in an increasingly agent-mediated economy. This is a deliberate choice:

- Personal AI owners have the strongest need for oversight. Unlike enterprises with IT departments, an individual running a personal AI has limited ability to manually monitor what their agent does. AATP gives them a structured way to review and evaluate their agent's decisions.

- Personal AI-to-AI interaction is the fastest-growing frontier. As personal AI server projects scale, millions of personal AI agents will begin interacting with service providers' agents, other personal agents, and marketplace agents. This creates the exact scenario where audit trails become essential.

- Personal adoption creates bottom-up pressure. If personal AI agents begin requesting AATP-audited transactions, service providers will face market pressure to support the standard. This is how many internet standards achieved adoption — not top-down from enterprises, but bottom-up from widespread individual use.

Enterprise AI agents (procurement, treasury, supply chain) are the natural second wave, where the regulatory compliance argument becomes dominant. But AATP is designed to be useful at the individual level first.

### 10.4 Why an Open Standard, Not a Product

AATP is deliberately positioned as an open standard rather than a commercial product. This is a strategic choice based on how infrastructure standards succeed:

- TCP/IP succeeded because it was not owned by any company. Everyone built on it.

- HTTP succeeded because it was an open standard. Even Microsoft adopted it instead of competing.

- OAuth 2.0 succeeded because Google and Facebook both adopted it rather than building proprietary alternatives.

- MCP and A2A succeeded because they were open-sourced and donated to the Linux Foundation.

An open audit standard does not threaten any existing player. Communication protocol developers (Anthropic, Google) are not building audit layers. Payment protocol developers (Coinbase, Stripe) are not building decision-recording systems. An open audit standard is complementary to all of them — it is more likely to be adopted as a layer in their stacks than to be competed against.

If AATP were a commercial product, major companies would have an incentive to build their own alternative. As an open standard, they have an incentive to adopt it.

## 11. Scope and Boundaries

### 11.1 What AATP Is

- A standard for recording AI agent decision-making in human-readable, tamper-proof format

- A set of mandatory decision points where records must be generated

- Integrity mechanisms that make records verifiable and tampering detectable

- Integration patterns for existing communication, payment, and identity protocols

- A framework for three-level audit (integrity, compliance, reasonableness)

### 11.2 Beyond Bilateral Commerce: Solo Decision Audit

As described in Section 4.5, AATP operates in three modes: bilateral, unilateral, and solo. Solo mode is particularly significant for AATP's scope because it means the standard is not limited to AI-to-AI commerce. A personal AI managing subscriptions, filtering emails, scheduling tasks, or monitoring a portfolio can use AATP in solo mode to give its principal a reviewable record of every significant decision — even when no counterparty is involved.

This has a direct consequence for adoption: AATP is useful from the moment a single agent is deployed, before any multi-agent ecosystem exists. Solo mode is not a degraded version of bilateral mode; it is a complete accountability solution for single-agent decision-making.

### 11.3 What AATP Is Not

- Not a communication protocol (uses A2A, MCP)

- Not a payment system (uses x402, AP2, or any other rail)

- Not an identity provider (uses W3C DIDs and VCs)

- Not a regulatory framework for any specific jurisdiction

- Not an AI alignment solution — it does not verify AI internal states

- Not a guarantee of honest behavior — it creates consequences for inconsistency

### 11.4 Core Invariants

The following properties define AATP's identity as a protocol. They are not implementation details or parameters that can be tuned per deployment. Removing or fundamentally altering any of these properties would produce a different protocol, not a variant of AATP. Future versions may extend these invariants but must not violate them.

This section is the sole authoritative definition of AATP's Core Invariants. Other documents (including the AATP Governance Addendum) reference these invariants but do not independently define them.

**Structural Invariants**

These invariants define the technical structure of AATP records and their verification:

**Invariant 1: Dual-Layer Model.** AATP maintains a strict separation between the Working Channel (Layer 1, where agents conduct their business communication) and the Audit Trail (Layer 2, where decision records are generated and sealed). These two layers serve fundamentally different purposes and must remain distinct. The Working Channel is optimized for efficiency; the Audit Trail is optimized for accountability. An implementation that merges agent communication and audit records into a single undifferentiated stream does not conform to AATP.

**Invariant 2: Narrative and Structured Data Duality.** Every audit record must contain both a human-readable natural language narrative and machine-readable structured data. Neither alone is sufficient. The narrative enables human judgment (Level 3 review); the structured data enables automated verification (Level 2 review). An implementation that captures only structured data, or only narrative text, does not conform to AATP.

**Invariant 3: Sealed Hash Chain.** Every audit record must be cryptographically sealed at creation time and linked to the previous record's seal, forming a tamper-evident chain. The specific hash algorithm and signature scheme may evolve (SHA-256 and Ed25519 in v0.1), but the property that records are immutable after creation and sequentially linked is invariant. An implementation that allows post-creation modification of records, or that stores records without chaining, does not conform to AATP.

**Invariant 4: Decision-Point Model.** Audit records are generated at defined decision moments in a transaction lifecycle, not as continuous streams or periodic snapshots alone. The eight core decision points (Section 4.2) define the normative minimum set of auditable moments. Periodic status records (Section 4.2.2) complement but do not replace decision-point records. An implementation that abandons the decision-point model in favor of purely time-based or volume-based logging does not conform to AATP.

**Invariant 5: Three-Level Review Separation.** AATP defines three distinct levels of audit review: integrity verification (Level 1, automated), conformance checking (Level 2, semi-automated), and reasonableness assessment (Level 3, human or advanced AI judgment). These three levels serve fundamentally different purposes and must remain separate. An implementation that collapses integrity and conformance into a single pass, or that eliminates the human-judgment level, does not conform to AATP.

**Governance Invariants**

These invariants define the accountability structure and authority model of AATP:

**Invariant 6: Agent and Auditor Independence.** The entity that creates audit records (the agent, via the Recorder) and the entity that reviews them (the auditor, via the Reviewer) must have separate identities and separate signing authority. An agent must not sign its own review findings. An implementation where the agent grades its own work does not conform to AATP.

**Invariant 7: Human Principal Sovereignty.** Every AATP audit trail must trace back to a human principal whose delegation authorizes the agent's actions. The protocol does not recognize autonomous AI authority. Consequences for audit findings are determined by the human principal, not by the protocol or the auditor. An implementation that removes the human principal from the accountability chain does not conform to AATP.

These seven invariants are intended to be stable across major versions. A proposal to change any invariant requires extraordinary justification and constitutes a proposal for a successor protocol, not an amendment to AATP. The procedure for proposing changes to Core Invariants is defined in the AATP Governance Addendum.

## 12. Honest Limitations and Strategic Context

Any standard proposal should be transparent about what it cannot do and what assumptions it makes about the future:

**The market is early, and that is intentional.** True autonomous AI-to-AI negotiation is in its earliest stages. AATP is designed to be ready when the market arrives, not to chase a market that doesn't yet exist. The cost of publishing an open specification now is near zero. The cost of establishing audit standards after millions of AI agents are already transacting without audit infrastructure would be enormous — retrofitting accountability is always harder than building it in. AATP's role in this early phase is to promote the development of personal AI deployment by giving owners a structured way to oversee their agents, reducing the barrier to trust that currently limits adoption.

**Adoption starts unilateral and grows bilateral.** Early adoption will primarily be in unilateral mode (one party recording). This provides less assurance than bilateral mode but is still valuable: it gives the adopting principal visibility into their own agent's behavior. As adoption spreads and agents increasingly encounter AATP-aware counterparties, bilateral mode becomes the norm. The transition is gradual, not sudden.

**High-frequency transactions require batching.** Per-transaction audit at $0.02–$0.06 is impractical for agents making hundreds of sub-$0.01 transactions daily. AATP addresses this at the conceptual level by establishing the principle that similar transactions may be aggregated into summary audit records (batch mode). The specific aggregation rules — what counts as 'similar,' how summaries are structured, what sampling methods are acceptable — are technical specification matters that will be developed based on implementation experience. The core principle is that auditability must scale with transaction volume.

**Narrative quality is enforced through incentive, not protocol.** The protocol cannot force an AI to write clear, detailed explanations. What it can do is create conditions where quality is visible and has consequences. Independent audit AIs can score narrative quality across multiple dimensions (specificity, consistency with structured data, reference to authorization scope). These scores inform the human principal, who decides how to respond — exactly as corporate internal audit informs the board. In later phases, audit scores may become visible to counterparties, creating market-level incentives.

**Legal status follows adoption, not the reverse.** No court has ruled on the evidentiary status of AI-generated audit records. AATP does not require legal recognition to be useful — its first-phase value is in giving principals oversight of their own agents, which needs no legal framework. However, as AATP records become widely used and their consistency-checking mechanisms prove reliable, they create a natural candidate for legal recognition as evidence of AI agent activity — similar to how email logs and database records became accepted as business records over time, not through legislation, but through established practice. The design is consistent with existing electronic transaction laws (E-SIGN Act, UETA) and common law agency doctrine, creating a foundation for future legal acceptance.

### 12.1 An Unresolved Design Tension: Narrative Attribution

One question AATP deliberately leaves open in v0.1: when an AI agent produces a narrative, whose statement is it legally? Is it the human principal's (because the agent acts under delegated authority)? The AI provider's (because their model generated the words)? The agent operator's (because they deployed and configured the system)?

AATP's position is that the narrative is a representation made under delegated authority of the human principal — analogous to a letter drafted by an employee and sent on company letterhead. The employee wrote the words, but the company is accountable for them because they were produced within the scope of employment. Similarly, the AI generated the narrative, but the principal is accountable because the agent operated within their delegated scope.

This framing is consistent with current agency law, but it has not been tested in court for AI agents specifically. This is an industry-wide challenge that will require judicial precedent or legislation to fully resolve. AATP's contribution is to create the evidentiary infrastructure that makes such resolution possible — without audit records, the question of attribution cannot even be meaningfully asked.

## 13. Path Forward

### 13.1 Immediate

- Publish the Technical Specification (v0.1) and this Conceptual Framework on GitHub

- Release a JSON Schema for audit record validation

- Build a reference implementation (Python) demonstrating a complete audited transaction

- Invite community feedback via GitHub Issues and Discussions

### 13.2 Near-Term

- Develop demo integrations with A2A and MCP reference implementations

- Engage with personal AI server communities (such as OpenClaw, Moltbot, Home Assistant AI) as first adopters

- Build example audit AI services that demonstrate Level 1–3 verification

- Present the framework to the Agentic AI Foundation and relevant working groups

- Collect implementation feedback and iterate on the specification

### 13.3 Long-Term

- Submit AATP to an established standards body (AAIF, IETF, or W3C)

- Develop a formal conformance testing suite

- Explore Zero-Knowledge Proof extensions for privacy-preserving compliance verification

- Evolve the standard based on real-world implementation experience and regulatory developments

### 13.4 Reference Implementation Primacy (Phase I)

AATP maintains a reference implementation (currently in Python) that serves as the authoritative behavioral specification of the protocol. The reference implementation is not merely an example or a convenience — it is the canonical arbiter of protocol semantics.

When ambiguity exists between the narrative specification (this document and the Technical Specification) and the reference implementation's behavior, the reference implementation governs. This is a deliberate design choice borrowed from successful protocol projects: a running, testable implementation resolves specification ambiguities faster and more reliably than committee deliberation.

**Phase I limitation:** This primacy of the reference implementation applies during the Founder Stewardship phase (v0.x) as defined in the AATP Governance Addendum. When AATP transitions to Phase II (Working Group Governance), the relationship between specification text and reference implementation will be subject to Working Group review. The Working Group may choose to maintain implementation primacy, to elevate the specification as authoritative, or to establish a formal reconciliation process. This transition is deliberate: in early stages, a running implementation resolves ambiguity faster than committee process; in later stages, multi-stakeholder governance may require specification primacy to ensure no single implementation has undue authority.

The reference implementation also includes a golden file — a known-correct audit record with pre-computed canonical bytes and hash — that serves as a cross-version consistency anchor. Any implementation that produces different output from the golden file's inputs is non-conformant, regardless of how the specification text might be interpreted.

Third-party implementations of AATP are welcome and encouraged. To claim AATP conformance, an implementation must pass the reference implementation's test suite and produce byte-identical output for the golden file's inputs. This is a low bar that ensures interoperability without restricting implementation freedom.

**AATP v0.x establishes the foundational model. Future revisions will evolve under an open process. If you believe AI economic activity should be accountable, transparent, and reviewable — by both machines and humans — we welcome your contribution.**