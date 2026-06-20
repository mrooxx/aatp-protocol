# AATP Agent Conformance Profile (ACP)

**v0.1 — Accepted for AATP v0.45 — Phase I steward (Founder Stewardship)**
**RFC: AATP-RFC-0001 · Status: Accepted (normative-optional profile)**

> **Status & provenance (AATP v0.45).** This document originated as an upstream
> *proposal* drafted from a landing application of AATP (ELMS — a collective,
> AI-driven, blockchain-settled liquidity pool), written to be read cold by AATP
> maintainers with no knowledge of the landing app. It is **accepted into AATP
> v0.45 as a normative-optional Profile**: a *view* over the seven Core Invariants
> (§11.4), sharpened into a named, testable predicate. It **adds no Core
> Invariant and changes none** (Governance Addendum §3). Conformance to AATP does
> not *require* ACP; ACP defines what "Tier-1 agent-instance conformance" *means*
> for implementations that choose to check or claim it. Open questions the landing
> application settled in practice are resolved in **§10**; those still open remain
> in §9 for Phase II (Working Group).

*It makes one thing AATP already implies into a first-class, named, testable
artifact: a **per-agent-instance behavioral conformance profile** — the checkable
answer to "is this a valid AATP agent?" — explicitly distinct from implementation
conformance and from agent quality.*

---

## 1. Summary

The question *"what counts as a qualified agent?"* hides three different
questions. AATP already answers two of them and deliberately refuses the third.
What it does **not** yet do is **package** the first answer as a single,
named, testable predicate that can be run against a *deployed agent's record
stream*. This proposal:

1. Names the three senses so they stop being conflated (§3).
2. Shows that the **Agent Conformance Profile (ACP)** — the behavioral predicate
   — is already fully implied by AATP's Core Invariants (§11.4); it needs
   packaging, not invention (§4).
3. Proposes a **three-tier conformance model** that slots ACP between AATP's
   existing *implementation* conformance and the deliberately-excluded *quality*
   question (§5).
4. Sketches the **conformance test** (§6) and why this helps AATP itself —
   bilateral mode, the reputation ecosystem, and the already-planned conformance
   suite (§7).
5. Reports how a landing application consumes ACP, as a real-world validation of
   the three-tier split (§8), and lists open questions for AATP (§9).

The intent is conservative: **no new invariant, no change to any existing one.**
ACP is a *view* over the seven Core Invariants, sharpened into a test.

## 2. Motivation

A standard that says "agents must be auditable" eventually has to answer, from a
counterparty's or an integrator's seat: *given this agent in front of me, is it a
valid AATP agent or not?* Today that judgment is reconstructable from the
framework, but only by a reader who can hold all seven invariants plus Principle
1 in their head and apply them to a record stream by hand. There is no single
artifact one can point an integration at and get back *conformant / not
conformant, and if not, which invariant failed*.

This matters most precisely where AATP is most valuable:

- **Bilateral mode (§4.5).** Cross-referenced accountability presumes the
  counterparty *is* an AATP agent. "Is it?" should be a check, not a vibe.
- **The reputation ecosystem (§7).** Aggregated audit data produces a *quality*
  signal. But a quality score is only meaningful over a population that is first
  established as *conformant* — otherwise you are averaging scores across things
  that are not even playing the same game.
- **Landing applications.** Any system that builds enforcement or governance on
  top of AATP (ELMS is one) needs a clean predicate "this is a valid AATP agent"
  to build role-specific checks on top of, without re-deriving the protocol.

## 3. Three senses of "qualified agent"

| Sense | The question | Who answers it today |
| --- | --- | --- |
| **(a) Implementation conformance** | Does this *codebase* implement AATP correctly? | AATP §13.4 — pass the reference test suite, byte-identical golden file. **Exists.** |
| **(b) Agent-instance behavioral conformance** | Does *this deployed agent's record stream* satisfy the invariants — over its life, not just at one record? | Implied by Invariants 1–7 + Principle 1, executed by Level 1 + Level 2 review (Invariant 5). **Implied, not packaged.** |
| **(c) Quality / competence** | Is the agent any *good* — are its decisions reasonable, is it trustworthy? | **Deliberately not defined by AATP** — §1.5 (reasonableness is the principal's to define), §6.2 (audit scores are emergent, not standard-defined), §9.2 (what AATP cannot verify). Surfaced *ex post* by Level 3 + emergent reputation. |

The proposal is entirely about **(b)**. It leaves **(a)** as-is and is careful to
keep **(c)** out — naming (c) explicitly is itself a contribution, because the
most common error is to demand that a standard certify (c), which AATP rightly
refuses.

## 4. ACP is already implied by the Core Invariants

The behavioral predicate is a direct reading of AATP's own normative text. Every
ACP clause below is *only* a restatement of an existing invariant or principle as
a per-agent, checkable obligation:

| ACP clause (over an agent's record stream) | Source in AATP |
| --- | --- |
| Every record traces to a human **Principal** under a bounded **delegation/authorization scope** | Principle 1 (§3); **Invariant 7** (Human Principal Sovereignty) |
| The agent's signing identity is **self-certifying** and **distinct from its auditor's** | **Invariant 6** (Agent–Auditor Independence) |
| Every record carries **both** narrative and structured data | **Invariant 2** (Narrative/Structured Duality) |
| Every record is **sealed** and **hash-chained** to its predecessor; immutable, sequentially linked, monotonic | **Invariant 3** (Sealed Hash Chain) |
| Records are generated at the **decision points** (the eight core points where applicable; periodic-status records present; extension points justified, not abusive) | **Invariant 4** (Decision-Point Model); §4.2 |
| Audit-trail records are kept **distinct from the working channel** | **Invariant 1** (Dual-Layer Model) |
| The stream **passes Level 1 (integrity) and Level 2 (conformance) review** | **Invariant 5** (Three-Level Review Separation) |

So ACP = "an agent whose record stream passes **Level 1 + Level 2** on an ongoing
basis, traces to a Principal, and is signed by an identity distinct from its
auditor." Nothing here is new. AATP already ships the *mechanism* (the Reviewer /
Levels 1–2). What is missing is the **name + the packaged predicate + a test
keyed to an agent instance rather than to an implementation.**

## 5. Proposal — a three-tier conformance model

Make conformance explicitly three-tiered, so the existing §13.4 work and any
future quality work each have a clear home:

- **Tier 0 — Implementation conformance** *(exists; §13.4)*: a *library* produces
  correct, golden-file-identical records. Binary, mechanical, one-time per build.
- **Tier 1 — Agent-instance behavioral conformance (the ACP — NEW)**: a *deployed
  agent's record stream* satisfies §4's clauses (= Levels 1–2 + Principal
  traceability + identity separation). Binary, checkable, *ongoing*. This is the
  answer to "is this a valid AATP agent?"
- **Tier 2 — Quality / competence (explicitly OUT OF SCOPE for the standard)**:
  reasonableness and trustworthiness. Not certified by AATP; produced *ex post* by
  Level 3 and the emergent reputation ecosystem (§6.2, §7). Named here only to
  fence it off from Tiers 0–1.

The contribution is the **partition itself** as much as ACP: it gives integrators
a precise vocabulary ("Tier-1 conformant, Tier-2 unscored") and stops the
category error of expecting a standard to certify Tier 2.

> **Stability.** ACP rides the **Core Invariants**, which §11.4 fixes as stable
> across major versions (changing one constitutes a successor protocol). So ACP is
> safe to depend on: the *test set* may gain cases, but the *predicate* it encodes
> does not drift.

## 6. The conformance test (sketch)

A reference ACP test takes an agent's chain (whole, or a sampled window) and the
referenced authorization scope, and returns a verdict plus the first failing
clause:

```
acp_check(chain, authorization) -> { conformant: bool, failures: [Clause] }
  L1  integrity:     every seal valid; chain links intact; sequence monotonic; no gaps
  L2  conformance:   every record has narrative AND structured; within authorization scope;
                     narrative ↔ structured-data consistency
      coverage:      decision-point model honored (8 core where applicable; periodic-status
                     present; extension points carry justification)
      principal:     every record traces to a human Principal (Inv 7)
      separation:    record-signing identity ∉ {its auditors} (Inv 6); dual-layer (Inv 1)
  → conformant iff all hold
```

This is implementable as an extension of the **already-planned conformance
testing suite** (§13.1, "Immediate") and naturally lives alongside the existing
`Reviewer` (Levels 1–2). Two design choices we recommend AATP settle:

- **Binary, not graded.** ACP should be a yes/no predicate; *gradations* belong to
  Tier 2 (quality), which AATP does not certify. Mixing them re-imports the
  category error.
- **Optionally attestable.** Consider letting a reviewer emit a signed statement
  *"agent X is ACP-conformant through epoch e"*. Landing apps that gate on
  conformance (below) can then consume a portable attestation rather than re-run
  the whole check — analogous to how reputation is already meant to be portable
  (§7).

## 7. Why this helps AATP (not only landing apps)

- **Bilateral mode gets a handshake.** "Is my counterparty a conformant agent?"
  becomes `acp_check`, run before trusting cross-referencing.
- **Reputation gets a clean denominator.** Tier-2 scores (§7) become "quality
  *among Tier-1-conformant agents*," which is the only population over which a
  quality average is meaningful.
- **§13.1's planned suite gets sharper.** Splitting Tier 0 (implementation) from
  Tier 1 (agent instance) clarifies what the suite tests: the golden file tests a
  *build*; ACP tests a *deployment*. Both are conformance; they are not the same
  test.
- **It stays true to AATP's philosophy.** ACP certifies *consistency/structure*,
  never *intent or quality* — exactly Principle 2 ("verify consistency, not
  intent") applied at the granularity of "is this a valid agent at all."

## 8. How a landing application consumes ACP (validation in practice)

ELMS — the landing app this proposal is written from — is a useful existence
proof of the three-tier split, because it independently arrived at the same
fences:

- ELMS presents **one Principal to AATP** (the capital pool); its decision module
  ("Decider") is an **AATP agent** acting under a **bounded, governed delegation
  scope**. That scope — ELMS calls it a `BoundarySet` — **is AATP's authorization
  scope**, specialized to be collectively governed and versioned. So Invariant 7's
  Principal↔delegation relation maps onto ELMS one-to-one.
- ELMS's audit levels **L1/L2/L3 are Invariant 5 verbatim**; its independent
  auditor is **Invariant 6**.
- ELMS would **adopt Tier-1 ACP as the predicate underneath its own role-fitness
  layer**: "a qualified Decider" = *ACP-conformant* **and** holds the installed
  decision key **and** stays within the `BoundarySet`. The first conjunct is
  wholly AATP's; only the latter two are ELMS-specific. ELMS does **not** want to
  re-define what an agent is — it wants to import ACP and build a thin layer on
  top.
- Crucially, ELMS **also refuses to certify Tier 2** (competence): its design
  selects competence by market and governance and polices it *ex post* (challenge
  → audit → enforce), never by an up-front quality gate. This independently
  reproduces AATP's §1.5/§6.2 stance — strong evidence the Tier-1/Tier-2 fence is
  the right place to draw the line.

The takeaway for AATP: a serious downstream consumer needs exactly Tier-1, wants
it portable/attestable, and agrees Tier-2 must stay out of the standard.

## 9. Open questions for AATP

1. **Sampling window.** Is ACP evaluated over the whole chain, or over a sampled
   window with a stated coverage bound? (Whole-chain is cleanest; sampling may be
   needed at scale — cf. batch mode, Principle 5.)
2. **Extension-point strictness.** How strictly does ACP judge extension-point
   *justification* (Invariant 4 / §4.2) before a stream is non-conformant vs.
   merely low-quality (Tier 2)?
3. **Attestation.** Should ACP-conformance be a signed, portable attestation
   (§6)? If so, what is its replay/expiry model, and who may issue it?
4. **Mode-relativity.** Do solo / unilateral / bilateral modes (§4.5) imply
   different ACP clause sets (e.g. counterparty cross-reference only applies in
   bilateral)?
5. **Relationship to the reputation suite (§7).** Should the conformance suite and
   the (quality) scoring suite share a harness but report two distinct outputs
   (Tier-1 boolean, Tier-2 score)?

## 10. Steward resolutions accepted in v0.45

The Phase I steward accepts the following on adoption; remaining items in §9 stay
open for the Working Group (Phase II). Nothing here adds or alters a Core Invariant.

- **The three-tier conformance model (§5) is adopted** as AATP's conformance
  vocabulary: Tier 0 (implementation, §13.4 golden file) · Tier 1 (this profile —
  agent-instance behavioral) · Tier 2 (quality, **out of scope** for the standard).
  Integrators may state "Tier-1 conformant, Tier-2 unscored."
- **ACP is binary, not graded** (§6). Gradations are Tier 2, which AATP does not
  certify; mixing them re-imports the category error.
- **Whole-chain is the default evaluation window** (§9.1). Sampled windows are
  deferred to, and governed by, the batch-mode guidance accreted in v0.45
  (Conceptual Framework Principle 5; cf. the LAEP profile §5.3) — a stated coverage
  bound, not silent truncation.
- **Attestation (§9.3) stays a Phase-I recommendation, not a mandate.** A reviewer
  *may* emit a signed "agent X is ACP-conformant through epoch e"; its
  replay/expiry model and issuer set are left to Phase II. The consuming landing
  application re-runs the predicate at its own gates rather than trusting an
  attestation blindly — evidence of the recommendation's adequacy, not of a need to
  mandate.

**Validation in practice (unchanged from §8).** ELMS, the landing application,
consumes Tier-1 ACP as the predicate beneath its own role-fitness layer ("a
qualified Decider" = *ACP-conformant* **and** holds the installed decision key
**and** stays within its governed `BoundarySet`), and independently refuses to
certify Tier 2 — reproducing the §1.5/§6.2 stance. This is the existence proof the
three-tier fence is drawn in the right place. Items §9.2 (extension-point
strictness), §9.4 (mode-relativity), and §9.5 (shared harness) were **not** forced
by the landing application and are honestly left open.

---

*Provenance: drafted 2026-06-13 by the ELMS project (a landing application of
AATP) as upstream feedback. References are to AATP Conceptual Framework v0.44 —
Principle 1 (§3), the eight decision points (§4.2), the three operating modes
(§4.5), the three review levels (§5), the reputation ecosystem (§7), what AATP
cannot verify (§9.2), the Core Invariants (§11.4), and the reference-implementation
/ conformance-suite path (§13.1, §13.4). No change to any Core Invariant is
proposed.*
