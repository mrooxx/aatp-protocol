# AATP Finance / Valuation Profile (sketch)

**v0.1 — Sketch for AATP v0.45 — Phase I steward (Founder Stewardship)**
**RFC: AATP-RFC-0003 · Status: Accepted as a *named sketch* (not a frozen profile)**

> **Honest scope.** This is a **skeleton**, not a finished profile. It is accepted
> into v0.45 only to (a) name the profile so financial adopters do not each invent
> incompatible decision points, and (b) record the extension points the landing
> application (ELMS) already uses in practice. It is **not** yet validated by an
> independent second financial adopter, and its decision-point set may change. It
> **adds no Core Invariant and changes none** (Governance Addendum §3); it is one
> domain instantiation of AATP's existing **extension decision points** mechanism
> (Conceptual Framework §4.2.1) — i.e. *using AATP as designed*, not extending it.

---

## 1. Why a Finance Profile

AATP defines eight core decision points (§4.2) plus an extension mechanism (§4.2.1)
for domain-specific moments. Financial agents — funds, treasuries, market-making
and valuation services — share a small set of recurring decision moments that are
**not** in the core eight but recur across every financial adopter:

- **Investment / allocation decisions** (enter, exit, rebalance a position).
- **Valuation / FairValue decisions** (set or attest a value basis for an asset
  that has no live market price).

If every adopter names these differently, cross-organization audit and the
reputation ecosystem (§7) fragment. Publishing one reusable set prevents that.

## 2. The extension decision points (initial set)

These are AATP extension decision points (§4.2.1), each carrying the standard dual
record (Invariant 2) and sealed into the chain (Invariant 3) like any record.

| Point | When emitted | Structured half (illustrative) | Narrative half |
| --- | --- | --- | --- |
| `INVESTMENT_DECISION` | entering / exiting / resizing a position | instrument, side, size, price basis, mandate clause invoked | why this trade is within the delegated mandate |
| `VALUATION_ATTESTATION` | setting a value basis for a non-market-priced asset | asset id, value, **basis source** (attested, *never* a self-computed price), as-of time | why this basis is defensible and within valuation authority |
| `REBALANCE_DECISION` *(optional)* | periodic mandate-driven rebalancing | target vs actual weights, drift, action set | why the rebalance honors the standing mandate |

The set is deliberately minimal. Adopters add their own extension points under
§4.2.1 with justification (Invariant 4); over-extension is itself an audit finding.

## 3. The honest fences (carried from ACP and LAEP)

- **Valuation attestations carry an *attested basis*, never a computed price.** A
  number the agent computed for itself is not an oracle. Where an independent value
  source exists, the attestation references it; where none exists, the record
  degrades to *"an honest, non-repudiable statement of a possibly-unverifiable
  value"* (LAEP §4 oracle gap) and must say so. This is Principle 2 at the valuation
  layer.
- **The profile certifies structure and scope, not investment quality.** "Was this
  a *good* trade?" is Tier-2 (ACP §5) — out of scope for the standard, surfaced
  *ex post* by Level 3 and reputation, never an up-front gate.

## 4. Validation in practice (the one existing consumer)

ELMS instantiates exactly this pattern: its `Decider` emits investment and
valuation decision records under a collectively-governed `BoundarySet` (= AATP's
authorization scope), and its valuation path consumes an **auditor-attested value
basis** (a `0x04` attestation), never a self-computed price — independently
reproducing the §3 fence. ELMS is **one** consumer; this profile should not be
frozen until a **second, independent** financial adopter exercises the same points.

## 5. Open questions for the Working Group (Phase II)

1. Is the initial three-point set right, or should `INVESTMENT_DECISION` split by
   lifecycle (open / adjust / close)?
2. Should the valuation attestation's "basis source" taxonomy be standardized
   (market / independent-appraisal / model-with-disclosed-inputs / unverifiable),
   or left to adopters?
3. Does a Finance Profile imply a *sampling/escalation* policy for L2 review at
   high-stakes vs routine trades (cf. the Operating-Cost report §6)?

---

*Provenance: drafted for AATP v0.45 by the ELMS project (a landing application of
AATP), distilling the investment and valuation decision points ELMS already uses
under AATP's §4.2.1 extension mechanism. Companion to the ACP and LAEP profiles and
the Operating-Cost report. No change to any Core Invariant is proposed.*
