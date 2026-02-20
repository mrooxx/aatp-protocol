# AATP Philosophical Memo: Multi-LLM Convergence and Approximating Truth

**Status:** Non-Normative — Philosophical Speculation  
**Date:** February 2026  
**Related:** AATP Conceptual Framework v0.44, Section 5 (Three-Level Review), Research Note on Audit-Derived Correction

> This document is a philosophical extension inspired by AATP's Level 3 reasonableness review mechanism. It does not define normative requirements and is not part of the protocol specification. It explores a broader epistemological question that emerges from AATP's design but exists independently of it.

---

## 1. The Core Proposition

When a sufficiently large number of independently developed LLMs evaluate the reasonableness of a decision, their aggregate judgment tends to approximate the expectations of the real world.

Truth itself is unattainable. But it can be approached through structured means.

---

## 2. Origin of the Idea

AATP's Level 3 review asks an auditor (human or AI) to assess whether an agent's decision was "reasonable." In typical deployment, this involves one or two auditor AIs chosen by the principal — sufficient for practical audit purposes.

However, a thought experiment arises: what happens when many LLMs independently evaluate the same decision? If each returns a binary score (reasonable / unreasonable), does the statistical distribution of these scores converge toward something meaningful — something that reflects how the real world actually works?

---

## 3. Theoretical Foundations

This proposition echoes several established concepts:

**Condorcet Jury Theorem (1785):** If each independent voter has a probability of being correct greater than 0.5, the probability of the majority being correct approaches 1 as the number of voters increases. The critical requirement is independence.

**Galton's Ox (1907):** 800 individuals estimated the weight of an ox. The median estimate was nearly identical to the actual weight. Individual errors, being diverse and uncorrelated, cancelled out in aggregate.

**Ensemble Methods in Machine Learning:** Random forests, boosting, and model stacking all exploit the principle that aggregating diverse weak learners produces a stronger learner. Diversity among models is the key to ensemble effectiveness.

**Prediction Markets:** Markets aggregate dispersed information from independent actors into prices that often outperform expert forecasts. The mechanism works precisely because participants have diverse information sources and incentives.

In all cases, the underlying principle is the same: diverse, independent judgments aggregate toward truth.

---

## 4. Applying the Principle to LLMs

LLMs can be viewed as a new class of cognitive agents. Each model encodes a compression of human knowledge, filtered through its specific training data, architecture, optimization process, and alignment method.

When multiple independently developed LLMs evaluate the same decision:
- Each brings a different "perspective" shaped by its training
- Each has different systematic biases
- If these biases are sufficiently uncorrelated, they tend to cancel in aggregate
- The resulting distribution of scores carries information about the real-world plausibility of the decision

Statistical methods can further refine this aggregation: weighting by model independence (penalizing models with high training data overlap), weighting by domain expertise (a finance-tuned model scores higher on financial decisions), and weighting by architectural diversity.

---

## 5. Critical Challenges

### 5.1 The Independence Problem

Current LLMs are not fully independent. Shared factors include:
- Common training corpora (Common Crawl, Wikipedia, Books3)
- Similar architectural foundations (Transformer variants)
- RLHF preference data drawn from overlapping annotator populations
- Knowledge distillation from earlier models into later ones

This means correlated errors are real. 100 models may unanimously agree on something that is wrong, because they all learned from the same biased source. The effective sample size is smaller than the apparent sample size.

**Mitigation:** Independence is a spectrum, not a binary. As the LLM ecosystem matures, training data diversifies, new architectures emerge (state-space models, mixture-of-experts, neurosymbolic systems), and more culturally diverse training pipelines are developed, the correlation between models decreases over time. The proposition becomes stronger as the ecosystem becomes more diverse.

### 5.2 The Grounding Problem

Humans approximate truth partly through direct sensory experience — seeing, touching, measuring. LLMs lack independent perceptual channels. Their "knowledge" of the world is mediated entirely through text (and increasingly, images and other modalities).

This means LLM consensus may converge not toward "how the world actually is" but toward "the consensus of human textual descriptions of how the world is." These are related but not identical.

**Mitigation:** Multimodal models with access to real-time data feeds (market prices, sensor data, satellite imagery) are beginning to close this gap. An LLM that can check a live commodity price before scoring a procurement decision has a partially independent perceptual channel.

### 5.3 The Objectivity Problem

Not all decisions have objectively "correct" reasonableness scores. Technical decisions (Is $0.007/credit within market range?) are more amenable to convergence than value-laden decisions (Should the agent prioritize cost over supplier loyalty?).

For value-laden decisions, multi-LLM aggregation may converge toward the dominant values in training data — which reflect particular cultural, economic, and temporal contexts — rather than toward any universal truth.

---

## 6. The Temporal Dimension

The proposition is not static. Its validity increases over time as:
- More independently developed models enter the ecosystem
- Training data sources diversify across languages, cultures, and domains
- New architectures reduce structural correlation between models
- Multimodal capabilities provide independent grounding channels
- Real-world feedback loops (audit outcomes, dispute resolutions) create empirical anchors

In this sense, multi-LLM convergence is itself an asymptotic process — it does not arrive at truth, but it progressively reduces the distance from it.

---

## 7. Relationship to AATP

AATP does not require this proposition to be true. AATP's Level 3 review functions perfectly well with a single auditor AI applying the principal's chosen standards. The protocol's value comes from traceability and accountability, not from truth approximation.

However, AATP's record format — structured narrative paired with machine-readable data, cryptographically sealed — happens to produce ideal inputs for multi-model evaluation. If the proposition holds, AATP records become not just audit artifacts but epistemological data points: each record is a testable claim about the world, and each review is an independent assessment of that claim.

This is an emergent possibility, not a design goal. AATP provides the observation window. What is observed through it — and what conclusions are drawn — remains outside the protocol's scope.

---

## 8. Summary

The proposition that independently developed LLMs, in aggregate, approximate real-world expectations is philosophically grounded in established principles of collective intelligence. Its practical validity depends on the degree of independence between models — a condition that is imperfect today but improving over time.

AATP neither depends on nor validates this proposition. But it creates the structured conditions under which the proposition could, in principle, be empirically tested.

Truth is unattainable. Convergence toward it is not.
