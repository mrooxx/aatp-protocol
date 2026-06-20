# AATP Ledger Anchoring & Evidence-Persistence Profile (LAEP)

**v0.1 — Accepted for AATP v0.45 — Phase I steward (Founder Stewardship)**
**RFC: AATP-RFC-0002 · Status: Accepted (normative-optional profile)**

> **Status & provenance (AATP v0.45).** This document originated as an upstream
> *proposal* drafted from a landing application of AATP (ELMS), written to be read
> cold. It is **accepted into AATP v0.45 as a normative-optional Profile** — one
> *optional externalization* (anchoring + evidence persistence) that rides existing
> invariants and **adds none** (Governance Addendum §3). It resolves the Conceptual
> Framework's standing "Merkle anchoring — scope and mandatory status to be
> determined based on implementation experience" item (v0.44 §13.3 / Roadmap
> Future): the implementation experience now exists. Anchoring remains **optional in
> v0.x** and carrier-neutral. The original §9 open questions the landing application
> settled are resolved in **§10**; the two real-chain frictions found while proving
> it on a public testnet are recorded as **field notes in §11**.

*It emerged from a design dialogue on the **simplest viable way to give AATP's
already-sealed record stream public, third-party non-repudiation and durable
evidence**. As with the ACP profile, the central contribution is **as much the
honest scope fence (the oracle gap, §4) as the mechanism (§3)**: it states
precisely what a public ledger can and cannot buy an accountability protocol, so
the most common error — selling tamper-evidence as truth-enforcement — is fenced
off by name.*

---

## 1. Summary

AATP **Invariant 3 (Sealed Hash Chain)** already gives every agent an internal,
sealed, hash-chained, monotonic record stream. What AATP does **not** yet name is
**where that chain lives, who witnesses it, and how the artifacts it references
survive** — i.e. how a *privately sealed* chain becomes a *publicly
non-repudiable* one whose referenced evidence cannot later be quietly lost. This
proposal:

1. Names the gap: "sealed" is necessary but not sufficient for accountability;
   the record half must also be **externally witnessed, non-repudiable, and
   durable against its own author's later destruction** (§2).
2. Gives a **minimal viable mechanism** — anchor the sealed chain (or a Merkle
   root of a batch) to a cheap, final, public ledger; persist referenced
   artifacts in content-addressed / permanent storage; handle mutable documents
   by append-only versioning (§3).
3. States the **scope fence** — what anchoring delivers (tamper-evidence,
   non-repudiation, external timestamp, durable existence, *ex-post*
   attributability) and what it provably **cannot** (correspondence to external
   reality — the **oracle gap**). The record↔fact binding comes from
   **multi-party cross-attestation**, never from the ledger itself (§4).
4. Lists the **required, non-optional sub-components** (identity↔key binding,
   anti-fork canonicalization, Merkle batching, data-availability tiering,
   encryption / selective disclosure) (§5).
5. Maps the whole thing back onto existing invariants — **no new invariant, no
   change to any existing one** (§6) — records the feasibility verdict from the
   dialogue (§7), and proposes a **sequenced, conditional roadmap** (§8) plus open
   questions for AATP (§9).

The intent is conservative and parallel to ACP: LAEP is a **view + an optional
externalization** over the Core Invariants, sharpened into a profile, with its
scope honestly fenced.

## 2. Motivation — "sealed" is not yet "witnessed, non-repudiable, durable"

Invariant 3 seals the chain *in the agent's own keeping*. Held privately, a sealed
hash chain still permits three failures that accountability cannot tolerate:

- **No external witness.** Nobody but the holder knows the chain — or any given
  record — existed at time *T*. Existence and timing are self-asserted.
- **Backdating by private re-sealing.** A holder who never published can re-seal a
  different history before first disclosure; the seal proves internal integrity,
  not *when* the content was committed.
- **Convenient loss.** The holder can simply fail to produce the chain, or "lose"
  an inconvenient referenced artifact.

AATP's foundational stance — *accountability is checking whether the record
matches the facts* — presupposes a record that is (a) **witnessed** by parties
other than its author, (b) **non-repudiable** and **anti-backdated**, and (c)
**durable** even against the author's own later destruction. None of (a)–(c) is an
*internal-seal* property; all three are **anchoring + persistence** properties.
That is the layer this profile names.

## 3. Mechanism (minimal viable)

**3.1 Anchoring.** Publish each sealed record — or, at scale, a Merkle **root** of
a batch (§5.3) — to a **cheap, fast-finality, public** ledger. The *carrier* can
be as minimal as a transaction's memo/data field. On chains where the cheapest way
to write a note is a value transfer, an agent may **self-transfer between two of
its own (cold) wallets**, putting the payload in the memo, value sloshing back and
forth at only gas cost. **The carrier is not the essence.** Value movement is
incidental; the essence is *a signed, hash-chained statement anchored to a public
immutable ordered log*. Where a chain offers a cheaper native data-write
primitive, use it instead — the profile is carrier-agnostic.

**3.2 The anchors are themselves a hash chain.** Each memo carries
`{ seq, prev_hash, payload_or_hash, sig, ts }`. The anchors therefore form their
**own** linked, self-ordering chain — tamper-evidence and ordering no longer
depend on the host chain's quirks (nonce interleaving, reorgs). **Canonical = the
anchored chain; a self-fork (two entries claiming the same `prev_hash`) is itself
admissible evidence of misbehavior**, not a tie to be silently resolved (§5.2).

**3.3 Evidence persistence (tiered).** A hash anchor proves an artifact's
integrity *if the artifact is produced*; it does not store it. Tier the storage by
the artifact's accountability weight:

- **Inline** — small records go straight into the payload.
- **Hash-anchor + off-chain store** — large artifacts: anchor the hash, keep the
  bytes in a content-addressed store. *Loss with an anchor present is already
  provable dereliction.*
- **Permanent store (e.g. Arweave)** — load-bearing artifacts (policies,
  decisions, contracts): pay-once, store-forever, so the bytes **cannot be made to
  disappear even by their author**. This is the only place bulk data belongs
  "on a chain-like medium"; IPFS alone is *not* persistent (needs pinning /
  Filecoin).

**3.4 Mutable documents — never overwrite, append a version.** "Permanently
immutable" and "updated daily" are not in tension once *immutability is
per-version*. A document becomes a **version hash chain**
(`v_n = { seq, prev_version_hash, content_or_diff_hash, sig, ts }`) — the **same
primitive as §3.2, at a different granularity**, and the two nest (a record entry
may reference a document version hash). Storage: full snapshots for small docs;
base + diffs (git-style) for large/frequently-changed ones; periodic full
"keyframes" between diffs. A small **mutable pointer** resolves "latest"; the
pointer's *own* update log is itself anchored, so "what was current at *T*" stays
auditable. **Anchor at meaningful checkpoints, not every autosave** — accountability
cares about committed states, not keystrokes.

**3.5 Privacy.** Encrypt-then-anchor: the ciphertext is durable/anchored,
readability is key-gated, and disclosure to an auditor is "reveal the key."
Fine-grained "prove property *P* of a document without revealing it" needs
ZK / commitments and is named here only as a later capability.

## 4. Scope fence — what anchoring does and does NOT deliver (the core contribution)

This section is the load-bearing one, and is deliberately parallel to how ACP
fences off Tier-2 quality.

**Delivers:**

- **Non-repudiation** — "this key committed to statement *S* at time *T*" cannot
  later be denied.
- **Tamper-evidence & anti-backdating** — the committed history cannot be
  rewritten or pre-dated after the fact.
- **External witness & timestamp** — existence and ordering attested by a public
  ledger, not by the author.
- **Durable existence** of referenced artifacts (with §3.3 Tier-permanent).
- ***Ex-post* attributability** — every action ties to a signing key.

**Does NOT deliver — the oracle gap:**

> A public ledger can guarantee the **record** half is honest. It can **never, by
> itself, guarantee the record corresponds to external reality.** You can prove
> *"X committed to S at T"*; you cannot prove *S is true of the world*. The ledger
> records even a false *S*, faithfully and immutably.

**The record↔fact binding is supplied by multi-party cross-attestation, not by the
ledger.** When the board AI, the independent auditor, counterparties, and the
operating team each anchor *their own* entries to the shared log, the independent
records **must mutually reconcile**; the cost of maintaining a consistent lie
across independent parties is what pins records to facts. AATP's "do the records
match the facts?" is precisely this reconciliation, executed across parties who
cannot all easily collude. **Where no independent witness exists** (a purely
internal valuation or chain-of-thought), cross-attestation is empty and the
property degrades to *"an honest, non-repudiable record of a possibly-false
claim."* That residue is real and must be disclosed, not papered over.

> **The single ontological failure mode is overclaiming** — presenting LAEP as a
> *truth-enforcement* layer. It is a *tamper-evident, cross-reconcilable
> accountability* layer. Kept to that claim, the design is sound; stretched past
> it, it is dishonest. This is exactly Principle 2 ("verify consistency, not
> intent") restated at the ledger layer.

**When the anchor is redundant — and when it earns its keep.** Anchoring is not
always worth its cost; state the boundary explicitly.

- **Redundant** when the relationship is **two-party, mutually trusting, with no
  third-party verifier and no anticipated dispute.** There, single-party custody —
  even a shared, versioned folder hosted by one side — is an adequate and *cheaper*
  evidence layer; a public anchor adds cost without buying a property anyone needs.
  (Consistent with treating the chain as a **commodity** and anchoring as
  **optional**: pay for neutrality only where trust is absent.)
- **Load-bearing** exactly when **any one** of three conditions holds:
  1. the parties **may come into dispute** — evidence then cannot sit in either
     party's custody;
  2. a **third party** (auditor, board, regulator, another shareholder, a
     cross-organization counterparty AI) must verify **without trusting the host**;
  3. one must be able to **prove the host itself did not tamper, withhold, or
     backdate**.

The reason single-party custody cannot substitute for anchoring here is
**structural, not incidental: custody does not remove trust, it relocates it to
the custodian** — and then fails precisely in the dispute it is meant to arbitrate.
And because **accountability must run in both directions** (principal↔operator: the
operator needs defense against an opportunistic or mis-remembering principal as much
as the reverse), evidence held by either party alone is disqualifying by
construction.

**Custody is not the protocol.** Grant, for argument, a perfect neutral durable
evidence layer. That is still only **storage**. The protocol is the **rules +
record semantics + cross-party verifiability that operate over the stored
contents**: which records must exist (the decision-point model), what each must
contain (narrative/structured duality), the mandate/authorization scope that bounds
them, the objective floor and hard caps, the review levels, and what "the records
match the facts" even means. A filing cabinet, however well-kept and well-witnessed,
checks **none** of this. Storage replaces the substrate; it does not replace the
standard.

**The bar rises with collective principals and multi-agent coordination** — two
cases where "just store the files" is not merely weaker but **structurally
insufficient**:

- **Collective / multi-shareholder principal.** When the principal is itself a
  *group* (ELMS's case — a collectively-governed capital pool), there is **no single
  trusted party** to host the files. Storage hosted by any one member re-imports
  single-party tamper-power *among the principals themselves*, and the members need
  a shared, neutral, verifiable substrate to agree on what the operator did and
  whether the **collectively-set** mandate was honored. Cross-attestation (above)
  *presupposes* exactly this shared substrate; a private folder cannot provide it.
- **Multi-agent coordination short of AGI.** Absent a single super-capable agent
  that could internalize every constraint, work is carried by **many narrow agents
  that must coordinate** — and coordination among non-omniscient, possibly
  mutually-distrusting agents **requires an explicit constraint set**: what each may
  do, what each must record, how they reconcile. That constraint set *is* a
  protocol. The only open question is how heavy it must be.

**Graduated profiles — a full and a lite AATP.** The constraint set need not be one
weight. **Full AATP** (eight decision points, three review levels, conformance,
public anchoring) is the right tool at a **trust boundary** — cross-party,
adversarial, third-party-verifiable accountability. *Intra-team* coordination —
agents inside one operating team that already share an interest — can run a
**simplified profile**: the hash-chain / versioning discipline plus a lighter record
set, *without* the full external-anchoring and independent-audit apparatus,
**escalating to the full profile only where the team's output crosses a trust
boundary** (faces the principal, an auditor, or a third party). This is the same
redundant-vs-load-bearing logic applied one level up: spend the protocol's heavy
machinery only at the seams where trust is absent.

## 5. Required (non-optional) sub-components

These are not enhancements; without them, responsibility leaks through the seams:

1. **Identity ↔ key binding & rotation.** The ledger attributes to a **key**;
   accountability must attribute to a **subject**. "My key was stolen" is a real
   attack/excuse surface. Needs a DID/vouching layer binding key→subject and a
   rotation scheme that preserves the attribution chain across key changes.
2. **Anti-fork canonicalization.** Spec rule: the anchored chain is canonical; a
   self-fork is admissible evidence of misbehavior. Prevents "anchor two
   histories, reveal the convenient one later."
3. **Merkle batching for scale.** At volume, anchor a **root** of *N* records per
   epoch, not one transaction per record. Keeps cost/throughput bounded and is the
   honest answer to "a chain that can record a lot" (you anchor *commitments*, not
   bulk data).
4. **Data-availability tiering** (§3.3) as an explicit per-artifact decision.
5. **Encryption + selective disclosure** (§3.5); ZK property-proofs as a later
   capability.

## 6. Relationship to existing AATP invariants (conservative — no new invariant)

| LAEP element | Rides on |
| --- | --- |
| The anchored chain *is* the sealed chain, externalized | **Invariant 3** (Sealed Hash Chain) |
| Payload retains narrative + structured; anchor carries the structured hash/ref | **Invariant 2** (Narrative/Structured Duality) |
| Multi-party cross-attestation = the review levels executed across **independent** parties on a shared log | **Invariant 5** (Three-Level Review), **Invariant 6** (Agent–Auditor Independence) |
| Every anchored record traces to a Principal via its signing identity | **Invariant 7** (Human Principal Sovereignty), Principle 1 |
| §4 scope fence | **Principle 2** (verify consistency, not intent) |
| Batch-root anchoring | Principle 5 (batch mode) |

Like ACP, **LAEP is a view + an optional externalization, not a new invariant.**
The *predicate* it encodes (anchor the already-sealed chain; persist its evidence;
bind facts only via cross-attestation) does not change anything AATP already
fixes.

## 7. Feasibility & soundness verdict (the dialogue's conclusion)

- **Technically feasible with off-the-shelf primitives.** Hash chains (git is
  one), content-addressed permanent storage (Arweave), anchoring, Merkle batching,
  PKI/DID, encryption. **No unsolved cryptography is required.**
- **No fatal logical flaw — *provided* the claim is scoped to §4.** The only real
  ontological risk is overclaiming truth-enforcement. The required sub-components
  (§5) close the practical seams (key↔subject, forks, scale, durability, privacy).

## 8. Roadmap — sequenced and conditional

0. **(now) Settle the unified entry schema** `{ seq, prev_hash, payload_or_hash,
   sig, ts }` — one shape serving **both** the action-record log (§3.2) and the
   document-version log (§3.4). This is the load-bearing artifact; everything else
   is plumbing on top of it.
1. **(weeks) Prove it on a commodity chain.** Anchor MVP1's already-sealed chain to
   one cheap, final public chain/testnet: one agent, two cold wallets, memo
   carrier; the AATP reader validates the anchored chain and runs the objective
   floor + hard numeric caps over the reconstructed state. This turns the Python
   reference from *simulated* into *actually anchored* — the smallest real "usable
   chain."
2. **Add evidence persistence** (§3.3 permanent tier) for load-bearing artifacts,
   plus the version-chain pattern (§3.4).
3. **Add a second independent party** (auditor / board AI) anchoring *its own*
   entries, and demonstrate **multi-party cross-attestation** closing the
   record↔fact gap on one concrete *reconcile-vs-diverge* case. This is the step
   that empirically tests §4's claim.
4. **Add the required sub-components** (§5): identity/key binding, anti-fork rule,
   Merkle batching.
5. **(only after adoption) Optional monetization.** If — and only if — AATP
   anchoring sees real volume, capture that settlement/gas demand with an
   **L2 / app-chain / rollup** (borrowed security, captured sequencer fees), never
   a from-scratch L1, and never as the starting point. **Demand first, capture
   second; the moat is the standard, not the chain.** Building the chain before the
   demand is a toll road with no cars.

## 9. Open questions for AATP

1. **Normativity.** Should anchoring be a *normative-optional* profile inside AATP,
   or left wholly to landing apps with AATP only blessing the seal format?
2. **Granularity.** Per-record anchoring vs per-epoch Merkle root — a profile
   parameter, or a fixed recommendation tied to Principle 5 batch mode?
3. **Cross-attestation semantics.** Does AATP want to standardize the multi-party
   reconcile rules (what counts as records "matching"), or only the single-agent
   anchor, leaving reconciliation to landing apps?
4. **Identity/key binding.** In scope for AATP, or delegated to an external DID
   standard with AATP only requiring *some* binding exist?
5. **Durability, provider-neutral.** Should AATP state the *durability property*
   required of the persistence tier (survives author destruction; integrity
   verifiable against anchor) rather than naming Arweave, to stay
   storage-neutral?
6. **A "lite" profile.** Should AATP bless a *simplified intra-team profile*
   (hash-chain + versioning discipline, lighter record set, no external anchoring)
   for coordination *within* a single trust domain, with a defined escalation to
   the full profile at trust boundaries? (Cf. the redundant-vs-load-bearing
   boundary in §4, and ACP's tiering.)

## 10. Steward resolutions accepted in v0.45

The Phase I steward accepts the following on adoption. Nothing here adds or alters
a Core Invariant; anchoring stays **optional in v0.x**.

1. **Normativity (§9.1) — resolved: normative-optional profile.** Anchoring is a
   *blessed optional profile* inside AATP (this document's status), not left wholly
   to landing apps and not mandated. AATP blesses the seal format and the anchored-
   chain shape (§3.2); apps choose whether to externalize.
2. **Granularity (§9.2) — resolved: a profile parameter, with batching as the scale
   path.** Per-record anchoring is admissible at low volume; per-epoch Merkle-root
   anchoring (§5.3) is the answer at scale, governed by Conceptual Framework
   Principle 5 (batch mode). *Proven so far:* single-record memo anchoring on a
   public testnet (§11). Merkle batching is specified (§5.3) but not yet run end-to-
   end — stated honestly, not claimed.
3. **Durability, provider-neutral (§9.5) — resolved: state the property, not the
   provider.** The persistence tier is required to deliver *survives author
   destruction* + *integrity verifiable against the anchor*; AATP names no specific
   store. The landing application's `PersistentStore` is an Arweave-ready **seam**
   with an in-memory fallback modelling exactly no-delete + substitution-evidence —
   demonstrating the property, not the vendor, is the contract.
4. **Identity ↔ key binding (§9.4) — resolved toward delegation.** AATP requires
   that *some* key→subject binding exist (§5.1) and delegates the binding scheme to
   an external DID/VC standard; AATP does not define its own. The "my key was
   stolen" attribution surface stays a required sub-component, satisfied externally.
5. **A "lite" profile (§9.6) — accepted in principle, spec deferred.** AATP blesses
   the **graduated full/lite** framing (§4): heavy machinery (anchoring + independent
   audit) at trust boundaries, a lighter hash-chain/versioning discipline within a
   single trust domain, escalating where output crosses a boundary. The concrete
   lite-profile clause set is deferred to a later profile revision.
6. **Cross-attestation semantics (§9.3) — left open (honestly).** The landing
   application proved the **single-producer record half** (a sealed chain anchored to
   a public testnet, independently re-verifiable — §11). **Multi-party
   cross-attestation** (§4 — the property that actually closes the oracle gap) is the
   *next* deepening (roadmap §8 step 3) and has **not** been run. The reconcile-rule
   standardization in §9.3 therefore stays a Working-Group question; the profile
   asserts the *mechanism* (§4), not a proven multi-party reconcile.

## 11. Real-chain field notes (v0.45)

Proving §8 step 1 on a public chain the producer does **not** control (an Ethereum
Sepolia testnet, faucet-funded throwaway wallet) surfaced two concrete frictions
that any anchoring-carrier implementation will hit. They are recorded here so the
carrier seam can be specified correctly upstream — both are *carrier/transport*
details, **not** changes to the anchored-chain semantics (§3.2), which were
untouched throughout.

1. **Do not assume the node holds the signing key.** A local/in-process EVM
   (`eth_tester`) holds the sender key, so a plain `send_transaction` signs and
   sends. A **public RPC does not hold your key** — the carrier must **sign locally
   and `send_raw_transaction`**. The carrier seam (`AnchorCarrier` / the reader) was
   unchanged; only the carrier *implementation* gained a local sign-and-send path.
   *Spec implication:* an anchoring-carrier interface must treat signing as the
   client's responsibility, never the node's.
2. **Calldata field name differs across providers: `input` vs `data`.** A public RPC
   returns a transaction's calldata under **`input`**; the in-process `eth_tester`
   returns it under **`data`**. A reader that rebuilds the anchored payload from the
   public chain must **prefer `input`, fall back to `data`**. *Spec implication:*
   anchored-payload readers must tolerate both field names (or the profile must
   pin one and require carriers to honor it).

**Outcome.** With both frictions handled, the landing application's sealed chain was
anchored as real Sepolia transactions; an independent reader rebuilt them **from
public blocks** and re-ran the objective floor to the **same verdict as the live
system** — over a chain the producer cannot control, re-readable by any third party
via the transaction hashes. This is the external public witness §2 and §8 require.
**Honest limit:** Sepolia is a *testnet* — exactly what step 1 required (non-producer-
controlled + third-party-verifiable). **Mainnet is a separate, money-bearing
decision, not part of this profile's proof.**

---

## Appendix A — design-dialogue trace (provenance of the shape)

This profile was distilled, in order, from a 2026-06-15 ELMS design dialogue. The
progression matters because each step *simplified* the previous one:

1. *"Time to build a usable chain so AATP can land?"* → challenged: the chain is
   not the binding constraint; adoption + the accountability layer are. Don't
   self-build an L1.
2. *"Then 'compliant chain' — users pick any chain that conforms."* → reframed the
   chain as a commodity backend; AATP becomes a chain-conformance standard, not a
   chain.
3. *"Simpler: just two accounts transferring cheaply; the record is enough."* →
   recognized as **chain-as-evidence-layer, not enforcement-layer**
   (detect/attribute, not prevent) — more consistent with "sell the accountability
   layer."
4. *"The transfer is just the carrier; the **memo** is the record — two cold
   wallets ping-ponging, each memo a journal entry."* → the minimal mechanism
   (§3.1–3.2); carrier ≠ payload.
5. *"Self-owned wallets aren't a problem — the board AI, auditors, AI↔AI, ops comms
   all write to the same logic; AATP just checks record-vs-fact."* → the
   **multi-party cross-attestation** engine (§4) that supplies the record↔fact
   binding the ledger alone cannot.
6. *"But I do want the artifacts themselves permanent — and how do daily updates
   work?"* → evidence persistence + append-only versioning (§3.3–3.4).
7. *"Could we launch our own chain and earn gas?"* → yes, but as a **conditional,
   post-adoption L2** monetization, not the starting point (§8.5).
8. *"Doesn't shareholder-hosted storage with version backup just replace
   ELMS/AATP?"* → no: **custody ≠ protocol**. Single-party custody only *relocates*
   trust to the custodian and fails in the very dispute it should arbitrate;
   storage is the easy 10%, while the record semantics + rules + cross-party
   verifiability are the 90% a folder never touches (§4).
9. *"And with multiple/collective shareholders, and many coordinating agents short
   of AGI, storage alone is clearly not enough — though intra-team it could be a
   simplified version."* → the **redundant-vs-load-bearing** boundary and
   **graduated (full / lite) profiles** (§4; §9.6).

The honest-boundary thread (§4) ran through every step: at each simplification the
question was *"what does this still NOT prove?"* — and the answer was always *the
oracle gap*, closed only by multi-party reconciliation, never by the ledger.

---

*Provenance: drafted 2026-06-15 by the ELMS project (a landing application of
AATP) as upstream feedback, from a design dialogue on minimal viable on-chain
anchoring. Companion to the Agent Conformance Profile (ACP) proposal v0.1.
References are to AATP Conceptual Framework v0.44 — Principle 1 and Principle 2
(§3), the three review levels (§5), the reputation/independence model (§6–§7), the
Core Invariants and especially Invariant 3 / Invariant 2 (§11.4), and batch mode
(Principle 5). **No change to any Core Invariant is proposed.***
