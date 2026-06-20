# AATP Operating-Cost & Token-Overhead Feasibility Report

**v0.1 — Accepted for AATP v0.45 — Phase I steward (Founder Stewardship)**
**Status: Accepted (non-normative report) · Companion to the LAEP and ACP profiles**

> **Status & provenance (AATP v0.45).** Accepted into v0.45 as a **non-normative**
> feasibility report — it sizes budgets and blesses cost-controlling patterns, but
> imposes no conformance requirement and **adds no Core Invariant**. All figures are
> order-of-magnitude and volatile; treat each as a power of ten, not a quote. The
> §6 implications are folded into v0.45 as guidance (batch mode = Principle 5 is
> also the primary *cost* lever; L1 is mechanical/no-LLM; L2 review MAY be sampled
> and/or run on a small model).

*Authored from a landing application of AATP (ELMS), but written to be read cold.
It estimates the **marginal running cost of operating under AATP** — the cost
*above* a baseline agent that simply acts without producing accountable records —
along the **two axes that actually cost money**: (1) on-chain anchoring & storage
("gas"), costed under the LAEP architecture (companion proposal), and (2) **LLM
token overhead**. All figures are **order-of-magnitude, 2026, and volatile** (gas /
AR-token / model prices move); they are not quotes. The central finding is a
**feasibility** claim, not a pricing claim: **cost is not the adoption barrier —
and the levers that keep it that way are the same design disciplines AATP/LAEP
already prescribe.***

---

## 1. Headline finding

- Operating under AATP has **two** cost axes. **On-chain is the small one; LLM
  tokens are the larger.**
- With the right design levers, the **marginal cost per record approaches zero**;
  total cost becomes a **small fixed overhead** set by *anchoring cadence*, *model
  tiering*, and *permanently-stored content volume* — **largely independent of
  record / activity volume**.
- The genuinely expensive configuration is the **naive** one — everything on-chain,
  a full record per micro-action, the frontier model for every step — which AATP
  and LAEP **already reject**. So bounded cost is a **design-discipline property,
  not an inherent tax** of the standard.

## 2. Scope and method

- **What is costed:** the *marginal* cost above a baseline agent that performs the
  same work but keeps no accountable record.
- **Two axes:** §3 on-chain (gas + permanent storage, under LAEP), §4 LLM tokens.
- **Caveats:** order-of-magnitude; 2026 prices; gas, Arweave (AR), and model
  pricing are all volatile; results depend heavily on **baseline verbosity**,
  **anchoring cadence**, and **review sampling rate**. Treat every number as a
  power-of-ten, not a figure.

## 3. On-chain cost (gas + storage)

**What does and does not cost.** Sealing, hash-chaining, and L1 integrity checks
are **deterministic code — free**. Only two things cost on-chain money:
**anchoring transactions** and **permanent storage**.

| Layer | Unit | Rough cost | Note |
| --- | --- | --- | --- |
| **L2 working layer** | per record, anchored individually | ~$0.005–0.03 | one tx with calldata on a cheap L2 (post-EIP-4844) |
| **L2 working layer** | per record, **batched** | ~$0.00001–0.001 | *N* records → one Merkle root (32 bytes) → amortized ≈ free |
| **Bitcoin root** | per epoch | **~$0** via OpenTimestamps / ~$0.5–5 own tx | OTS aggregates many roots into one BTC tx; cost is **independent of record count** |
| **Arweave content** | per MB, **one-time** | ~$0.005–0.02 (single-$ per GB) | only **load-bearing** artifacts; a typical doc ≈ cents, permanent |

**The lever is Merkle batching (LAEP §5.3):** once records are batched into per-epoch
roots, **cost scales with anchoring *cadence*, not record *count*.** Two scenarios:

- **Single agent, ~200 records/day:** unbatched ≈ **$60/mo**; batched ≈ **$1–3/mo**;
  Bitcoin (OTS) ≈ $0; Arweave (≈10 docs/day) ≈ **$3/mo**.
- **Busy collective fund, ~100k records/day:** unbatched ≈ **$30k/mo** (this is
  *why* you batch); batched (root every few minutes) ≈ **$100–300/mo**, *nearly
  flat in the 100k figure*; Bitcoin ≈ $0–60/mo; Arweave ≈ per-GB stored.

**On-chain cost drivers:** anchoring frequency; permanently-stored content volume;
own-BTC-tx vs OTS. **Not** the number of records.

## 4. LLM token overhead

**What does and does not cost tokens.** Sealing / hashing / L1 = **0 tokens**.
Only two activities consume tokens:

1. **Generating the dual record** (narrative + structured) at each decision point.
2. **L2 conformance review** — *if* performed by an LLM (narrative↔structured
   consistency + within-scope). L3 quality is *ex-post* / emergent, not a
   per-action cost.

| Item | Tokens | Note |
| --- | --- | --- |
| Record generation (narrative + structured) | **+200–500 output** | the genuinely-new part is mostly the *structured* half |
| L2 review verdict | +~200 output + input | input (record + rules) is large but **cacheable** |
| Rules / BoundarySet / schema in context | +1–5k **input**/call | mostly static → cheap under **prompt caching** |

→ The expensive (non-cached **output**) portion is roughly **+300–700 output tokens
per record**, plus several-k cacheable input.

**It is a percentage, and it depends on baseline weight.**

- **Analysis-heavy decider** (already burning 10k–50k+ tokens reading data and
  reasoning): AATP ≈ **+5–20%**.
- **Trivial high-frequency micro-action** (a few-hundred-token rule-based step):
  a *full* record could **more than double** it — which is precisely the case for
  the **lite profile + batching + periodic-status records** (LAEP §4 graduated
  profiles), *not* a full record per micro-action.
- **Net < gross:** a well-designed agent **already** emits a rationale; the truly
  additive cost is the *structure* and the *independent review*, not the
  explanation itself.

**Two levers (the token-side analogue of batching):**

1. **Model tiering.** Don't use the frontier model to *format records* or *run L2
   review* — use a small cheap model (Haiku-class). Token **count** is similar but
   token **cost** drops ~10–20×. Reserve the expensive model for the **decision
   itself**. This is the biggest lever on the dollar side.
2. **Profile / granularity.** Lite profile + batch + periodic status for
   high-frequency, low-stakes work; full record + review only at **decision points
   that matter** and **trust boundaries**.

## 5. Combined picture — bottom line

- **Per record:** on-chain a fraction of a cent (batched) + a few-hundred output
  tokens.
- **Relative to what is governed** (a fund, capital allocation): **negligible** —
  on-chain **pennies-to-dollars per agent per month**; token surcharge a **modest
  single-digit-to-~20%** in the realistic (analysis-heavy + tiered-model) case.
- **Cost scales with *decision points recorded* × *anchoring cadence*, not with
  activity volume or how much the agent thinks.**
- The cost-controlling levers — **batching, model tiering, graduated profiles** —
  are the **same disciplines** LAEP and ACP already prescribe. Feasibility and good
  design point the same way.

> **The only way to make AATP expensive is to defeat its own design:** put
> everything on-chain, write a full record per micro-action, and run every step on
> the frontier model. That is the naive baseline the standard already argues
> against — so "is AATP too costly to run?" reduces to "did the implementer follow
> the standard's own guidance?"

## 6. Implications for AATP

1. **Cost is not a conformance barrier.** Good news for adoption; worth stating
   plainly so integrators don't assume on-chain accountability is prohibitive.
2. **The standard may want to *bless the cost-controlling patterns*** so
   implementers don't fall into the naive-expensive version:
   - Batching / sampling already lives in **Principle 5**; the report shows it is
     also the primary *cost* lever, not only a *scale* lever.
   - A **lite profile** (cf. LAEP §9.6) bounds the token tax on high-frequency work.
   - Explicit guidance that **L1 is mechanical (no LLM)** and **L2 review MAY be
     sampled and/or run on a small model** would prevent a common, avoidable
     blow-up.
3. **Open questions for AATP:**
   - Should AATP state a **non-normative cost model** (this report, refined) so
     adopters can size budgets?
   - Should **L2 review** carry a stated **sampling/escalation policy** (e.g. full
     review at high-stakes decision points, sampled elsewhere) as part of
     conformance, or is that wholly the integrator's call?
   - Should the standard recommend (without mandating) **model tiering** for
     record-formatting and review, to keep conformance affordable?

---

*Provenance: drafted 2026-06-15 by the ELMS project from a directional cost
discussion. Companion to the **LAEP** anchoring proposal (the architecture costed
in §3) and the **ACP** proposal. On-chain figures assume the LAEP layered design
(L2 working layer + Bitcoin deep-root via OpenTimestamps + Arweave for permanent
content). Token figures assume AATP's dual-record requirement (Invariant 2), the
decision-point model (Invariant 4), and three-level review (Invariant 5), with L1
mechanical and L2 optionally LLM-based. All figures order-of-magnitude; no change
to any Core Invariant is proposed.*
