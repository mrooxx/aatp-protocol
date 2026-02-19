# AATP Roadmap

**Current phase: v0.x — Founder Stewardship**

This roadmap describes the planned development of AATP's reference implementation and supporting tools. The Conceptual Framework (v0.44) and Governance Addendum (v0.21) are complete and stable. What follows is the path from specification to working code.

AATP follows a "can run before can promote" philosophy: no public outreach until there is executable code that anyone can clone, run, and see results from.

---

## ✅ Completed

- Conceptual Framework v0.44
- Governance Addendum v0.21
- Architecture diagrams (5 Mermaid diagrams covering all three modes + implementation architecture)
- GitHub repository and documentation

## 🔨 In Progress: Core SDK (`aatp_core`)

The Python reference implementation. All code in this package is deterministic — zero LLM dependencies.

**Modules:**

| Module | Purpose | Status |
|--------|---------|--------|
| `record.py` | Pydantic data model for audit records | In progress |
| `canonical.py` | RFC 8785 JSON canonicalization (via existing library) | In progress |
| `crypto.py` | Ed25519 key management, SHA-256 hashing, record signing | In progress |
| `chain.py` | Hash chain construction, integrity verification | In progress |
| `session.py` | Session lifecycle orchestration (start → record → end) | In progress |
| `storage.py` | Local storage backend (JSON files, abstractable) | In progress |
| `verifier.py` | Level 1 + Level 2 automated verification | In progress |

**Key deliverables:**

- JSON Schema for audit record validation (auto-generated from Pydantic model)
- Golden file: a known-correct audit record with pre-computed hashes for cross-implementation testing
- Technical Specification v0.1 (living draft, maintained alongside code)
- **Spec v0.1 Freeze:** once the SDK API stabilizes, the Technical Specification will be frozen for external consumption. No structural changes after this point without a formal RFC.

## 🔜 Next: Demos

### Solo Mode Demo

A personal AI agent managing subscriptions and finances, generating auditable decision records. Runs entirely offline with mock data — no API keys required.

```bash
git clone https://github.com/mrooxx/aatp-protocol.git
cd aatp-protocol
pip install -e .
python examples/demo_solo.py
```

### Bilateral Mode Demo + Tamper Detection

Two agents transacting with cross-referenced audit trails. Includes a tamper detection demo showing what happens when a record is modified after creation — with diff output showing exactly what was changed.

### CLI Tool

Human-readable viewer for audit trails:

```bash
python -m tools.aatp_cli view examples/output/trail.json
```

## 📋 Planned: Real Agent Integration

- Connect `aatp_core` to a real LLM agent (Claude, GPT, or local model)
- Demonstrate Level 3 reasonableness review by an independent audit AI
- Evaluate integration with personal AI server platforms (OpenClaw, Home Assistant AI)

## 🔮 Future

- Merkle tree anchoring — periodic publication of chain summaries to external registries (blockchain or timestamp authority) for third-party-verifiable tamper evidence. Optional in v0.x; scope and mandatory status to be determined based on implementation experience.
- Threat model document — formal analysis of replay attacks, key rotation, storage corruption, clock manipulation, and other protocol-level security concerns
- `pip install aatp` — PyPI package (after API stabilization)
- MCP Tool Server — wrap Recorder and Reviewer as standard MCP tools
- Conformance test suite for third-party implementations
- Community outreach (Show HN, personal AI server communities, AAIF)
- Submission to a standards body (AAIF, IETF, or W3C) — after 3+ independent implementations and a completed conformance test suite

---

## Design Constraints

These constraints apply throughout development:

1. **Zero LLM dependency in the SDK.** `aatp_core` is entirely deterministic. LLMs participate only at the agent layer and audit layer, never in record creation or verification. (Principle 6: Deterministic Security, Probabilistic Intelligence)

2. **Zero external dependency for demos.** `git clone → pip install -e . → python run` must work without API keys, network access, or external services.

3. **Documentation is frozen unless formal RFC accepted.** The Conceptual Framework and Governance Addendum are stable. Changes require a documented RFC with public rationale, consistent with the governance process defined in the Addendum.

---

*This roadmap is a living document. Progress updates will be reflected here as milestones are reached.*
