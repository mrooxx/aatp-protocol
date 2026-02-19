# AATP Governance Addendum v0.21

*Draft — Founder Governance Phase*

**Changxiao Huang (Norland), Founding Steward**

*February 2026 — Corresponds to Conceptual Framework v0.44*

*Released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)*

---

## 1. Purpose

This Addendum defines the governance model for AATP during its early-stage development (v0.x phase).

The objectives are:

- Preserve conceptual integrity of the protocol.
- Provide clear evolution mechanisms.
- Avoid fragmentation during formative adoption.
- Establish a pathway toward eventual multi-stakeholder governance.

This governance model applies to the Technical Specification and Reference Implementation. The Conceptual Framework remains a descriptive document and is not subject to normative version control, with the exception of the Core Invariants defined in Section 11.4 of the Conceptual Framework, which are normative.

## 2. Governance Phases

AATP governance evolves through three phases:

### Phase I — Founder Stewardship (v0.x)

- A single founding maintainer (or founding group) serves as protocol steward.
- All normative changes require maintainer approval.
- Breaking changes are allowed.
- Rapid iteration is prioritized over backward compatibility.

*This is the current phase.*

### Phase II — Working Group Governance (v1.x)

Triggered when any of the following conditions are met:

- At least three independent implementations exist.
- At least one third-party audit service operates on AATP records.
- Cumulative valid AATP audit records across all known implementations exceed a threshold established by the founding maintainer (initial target: 100,000 records), indicating meaningful real-world usage.

Governance structure:

- AATP Working Group established.
- RFC process formalized.
- Breaking changes require supermajority approval.
- Reference implementation no longer solely authoritative (see Section 6).

### Phase III — Foundation-Level Governance

Triggered by:

- Industry adoption across multiple ecosystems.
- Submission to or integration with a standards body (e.g., IETF-style process).

Governance becomes multi-stakeholder and neutral. Founder authority transitions to stewardship role.

## 3. Core Invariants

The Core Invariants that define AATP's protocol identity are specified in the Conceptual Framework, Section 11.4. That section is the sole authoritative source for the content and number of invariants.

This governance document defines the procedures for proposing changes to those invariants:

- Any proposal to modify, remove, or add a Core Invariant constitutes a proposal for a successor protocol, not an amendment to AATP.
- In Phase I, such proposals require explicit steward approval and must include extraordinary justification documented publicly.
- In Phase II, such proposals require unanimous Working Group approval.
- In Phase III, such proposals follow the standards body's process for major revisions.

Any implementation that violates any Core Invariant as defined in the Conceptual Framework may not claim AATP compatibility, regardless of governance phase.

## 4. Versioning Policy

### 4.1 Version Classes

- **v0.x** — Experimental. Breaking changes permitted.
- **v1.x** — Stable Core. Backward compatibility required unless major revision approved.
- **v2.x** — Major Revision. Structural changes allowed under Working Group vote.

### 4.2 Breaking Change Definition

A change is breaking if it:

- Invalidates existing audit records.
- Alters mandatory decision points.
- Changes cryptographic integrity guarantees.
- Removes structured-narrative duality.

Breaking changes in Phase I require explicit steward approval.

## 5. RFC Process (Phase I Simplified)

During Founder Stewardship phase:

- Proposals submitted via GitHub Issues.
- Maintainer may: Accept, Reject, or Request modification.
- Rejection must include a public written rationale. The proposer retains the right to request a community discussion within 30 days of rejection. The maintainer retains final decision authority during Phase I, but must engage with the discussion in good faith.
- Accepted proposals receive RFC identifier: AATP-RFC-000X.
- RFC merged into Technical Specification repository.

In Phase II, RFC approval will require multi-party review.

## 6. Reference Implementation Authority

During Phase I:

The official reference implementation defines behavioral interpretation in cases where specification language is ambiguous. Specification text governs normative requirements. Reference implementation governs operational clarification.

This ensures consistent implementation during early adoption.

**Phase transition:** When AATP enters Phase II, the Working Group will review and determine the ongoing relationship between specification text and reference implementation. The Working Group may choose to maintain implementation primacy, elevate the specification as authoritative, or establish a formal reconciliation process. This governance decision will be documented as an RFC.

## 7. Compatibility and Naming

These semantic contracts are normative conformance requirements for AATP v0.21.

Implementations may describe themselves as:

- "AATP-compatible"
- "Implements AATP vX.Y"

Only implementations conforming to published specification, satisfying all Core Invariants (as defined in the Conceptual Framework, Section 11.4), and passing conformance tests (when available) may claim compatibility.

Use of the name "AATP" for materially altered protocols is discouraged and may be restricted by future trademark governance.

## 8. Transparency and Openness

All governance decisions during Phase I must:

- Be documented publicly.
- Include rationale.
- Be archived permanently.

Governance authority derives from transparency, not secrecy.

## 9. Transition Commitment

Founder Stewardship is explicitly temporary.

The founding maintainer commits to publicly announcing a Phase II transition plan within 90 days of any Phase II triggering condition (Section 2) being met. This announcement must include a proposed timeline, a process for establishing the Working Group, and an invitation for community participation.

**AATP is designed to outlive its founder.**
