# Open Secure AI Alliance contribution path

## Status

This is an independent technical roadmap. HERESY-SEC is not claiming membership in,
endorsement by, or an accepted contribution to the Open Secure AI Alliance.

## Why the fit is real

NVIDIA announced the Open Secure AI Alliance on 27 July 2026 as a multi-vendor effort
to develop and share open technologies, techniques and tools for securing software and
AI agents. Its published framing is deliberately broader than model weights: the
relevant stack includes identity, permissions, harnesses, guardrails, logs and
evaluation.

The motivating Hugging Face incident also exposed two distinct requirements:

1. defenders need access to capable open-weight models that can run privately when
   hosted models cannot process real attack material; and
2. a forensic system must organize and verify very large action histories regardless
   of which model analyzes them.

Hugging Face reported using AI agents to analyze more than 17,000 recorded events,
reconstruct the intrusion and keep sensitive material on its own infrastructure. That
is exactly the scale at which reproducible envelopes, lineage and replay become useful.

Primary sources:

- [NVIDIA: Industry Leaders Unite in Open Secure AI Alliance for AI Safety and Security](https://blogs.nvidia.com/blog/open-secure-ai-alliance/)
- [Hugging Face: Security incident disclosure — July 2026](https://huggingface.co/blog/security-incident-july-2026)
- [NVIDIA: Six Agent Harness Capabilities for Higher Model Performance](https://developer.nvidia.com/blog/six-agent-harness-capabilities-for-higher-model-performance/)
- [Linux Foundation: Akrites launch](https://www.linuxfoundation.org/press/linux-foundation-and-industry-leaders-launch-akrites-to-defend-critical-open-source-software-against-ai-enabled-cyber-threats)

## The proposed contribution

HERESY-SEC should become a vendor-neutral evidence and replay layer between agent
harnesses and security operations:

```text
open or closed model
        |
agent harness / security scanner
        |
HERESY-SEC capture adapter
        |
canonical action + deterministic policy
        |
decision + chained receipt + portable replay corpus
```

The model may discover, correlate or explain. HERESY-SEC records what was proposed,
which explicit rule or boundary decided it, and whether another implementation can
reproduce the result. It must never present model consensus as proof.

## Stack mapping

| Alliance-level concern | Present v0.2.0 contract | Intended extension |
| --- | --- | --- |
| Agent identity | `producer.agent_id` | Validate SPIFFE-compatible workload IDs |
| Workload identity | Optional `producer.workload_id` | SPIFFE/SPIRE verification adapter |
| Model diversity | `OPEN_WEIGHT`, `CLOSED`, `NO_MODEL`, `UNKNOWN` | Adapter manifests and capability declarations |
| Harness provenance | Harness ID and optional SHA-256 | Signed harness/build attestations |
| Permissions | Requested authority and policy boundaries | Capability profiles mapped from real runtimes |
| Guardrails | Hard checks plus pinned action-graph, holonomy and Shadow Guard gates | Cross-language geometry vectors and interoperable policy vocabulary |
| Logs | Exact raw records plus normalized actions | Streaming capture API with bounded backpressure |
| Evaluation | Exact replay plus T1–T8 classical/geometry fixtures | Public incident fixtures and independent conformance suites |
| Findings exchange | Canonical decisions | SARIF 2.1.0 exporter |
| Supply-chain trust | Source-bundle SHA-256 | in-toto/Sigstore-compatible attestations |
| Human coordination | `REVIEW` effect | Review receipts and coordinated-disclosure handoff |

## Contribution milestones

### v0.1.x — prove the deterministic nucleus

- keep the runtime standard-library-only and offline;
- publish versioned action, producer, policy, decision and receipt contracts;
- maintain cross-version golden vectors;
- fuzz malformed JSON and policy boundaries;
- demonstrate replay on thousands of synthetic events.

### v0.2.x — geometry without authority expansion

- maintain a bounded, integer/rational geometry profile;
- publish stable action-graph, curvature, spectral, holonomy and registry fixtures;
- keep geometric evidence subordinate to hard classical boundaries;
- seek independent reproduction of geometry identities and receipts.

### v0.3.x — interoperability without authority expansion

- add capture adapters for common JSONL agent traces;
- add SARIF export for decisions and reason codes;
- publish a conformance CLI for third-party harnesses;
- add bounded streaming with explicit byte and record limits;
- integrate optional QSOLAI proposal capture without executing proposals.

Adapters translate evidence. They must not silently grant file, process or network
authority.

### v0.4.x — authenticated provenance

- define SPIFFE-compatible workload identity validation;
- add detached signature and transparency-log hooks;
- map source bundles and harness builds to in-toto/Sigstore-style attestations;
- retain unsigned receipts as integrity evidence while clearly labeling them
  unauthenticated.

No custom cryptography should be invented.

### v0.5.x — reproducible multi-model forensics

- capture competing findings from open and closed models;
- use deterministic adjudication after capture;
- preserve unresolved disagreement;
- publish synthetic incident corpora, mutation tests and replay benchmarks;
- provide optional SPECTRAL sonification from already-committed decision events.

Sonification is an alert representation, not evidence and not a detector.

### Alliance-ready contribution candidate

A credible external proposal should include:

- stable schemas with compatibility policy;
- independent implementations or cross-language test vectors;
- a threat model and security review;
- reproducible benchmarks at realistic event volumes;
- clear integration points with identity, harness and disclosure projects;
- governance that does not depend on one model vendor or one organization.

## What HERESY-SEC should not become

- a wrapper around one vendor's model API;
- an autonomous offensive system;
- a scanner that treats unverified model prose as a confirmed vulnerability;
- a custom replacement for mature identity, signature or disclosure standards;
- a telemetry vacuum that exports incident data by default;
- an Alliance-branded project without permission.

The useful niche is narrow and strong: portable evidence, deterministic boundaries and
exact replay across a heterogeneous defensive AI ecosystem.
