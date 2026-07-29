# HERESY-GEOM integration notes

## Status

**Attributed external proposal; not implemented in HERESY-SEC v0.1.0.**

A title-page screenshot supplied to the project on 30 July 2026 identifies:

> HERESY-GEOM — A Deterministic Geometric Upgrade Architecture for HERESY-SEC

The screenshot attributes the document to **DeltaKingZero / Dr. John Robitaille**,
dates it **2026-07-27 UTC**, and describes it as an academic, falsifiable,
replay-stable and non-heuristic architectural specification.

The visible title page names:

- action graphs;
- discrete curvature;
- holonomy gates;
- shadow-guard integrity;
- atom-addressable policy objects;
- an impossible-configuration registry;
- a KR-MPGM spine.

Its visible lineage note says it builds on the public
`multimodalas/HERESY-SEC` determinism contract without claiming ownership of that
project. The canonical maintained project has since moved to
[`QSOLKCB/HERESY-SEC`](https://github.com/QSOLKCB/HERESY-SEC).

Only the title page and the beginning of the abstract were available. This document
therefore records an integration boundary, not an interpretation of unseen formulas
or a claim that the proposal has been implemented.

## Why implementation is deferred

HERESY-SEC cannot assign guessed meanings to geometric terms and still call the result
deterministic or falsifiable. A conforming implementation needs the complete normative
specification, including:

1. exact definitions and domains for every geometric object;
2. canonical encodings, ordering rules and duplicate handling;
3. integer, fixed-point or explicitly rational arithmetic rules;
4. graph rules for loops, parallel edges, disconnected components and orientation;
5. overflow, bound and invalid-state behavior;
6. decision precedence and interaction with existing hard boundaries;
7. worked examples and adversarial counterexamples;
8. golden conformance vectors with expected identities and decisions;
9. licence and redistribution terms for specification text or reference code.

Without those materials, code bearing the HERESY-GEOM name would be an unverifiable
look-alike rather than a faithful implementation.

## Non-negotiable integration contract

Any future geometric extension must preserve the HERESY-SEC runtime architecture:

- inputs remain untrusted descriptions and are never executed;
- exact bytes are captured before parsing;
- floats, duplicate keys, cycles, unsafe integers and unexpected fields remain
  rejected in identity-bearing structures;
- graph streams use explicit, unique sequences and canonical endpoint identities;
- any rational quantity has one canonical numerator/denominator form;
- domain-separated SHA-256 commits every new object and witness;
- hard authority, network, process, file, IPC and size boundaries execute before any
  geometric rule;
- geometric evidence may preserve a decision or make it stricter, but may never turn a
  hard-boundary `DENY` into `REVIEW` or `ALLOW`;
- exact replay fails on any changed byte, source bundle, registry, graph, witness or
  receipt link;
- no host clock, entropy, network response or model output enters canonical identity.

## Proposed module boundary

Once the normative specification is available, the extension should be isolated
behind a versioned contract rather than mixed into the v1 action schema:

```text
captured action stream
        |
        v
existing hard boundaries
        |
        v
canonical action graph ----> impossible-configuration registry
        |                                  |
        v                                  v
geometric witnesses --------------> deterministic gate result
        |
        v
existing policy precedence, receipts, manifest and exact replay
```

Candidate artifacts, subject to the actual specification, would be versioned objects
such as `action-graph.json`, `geometric-witnesses.json` and
`impossible-configurations.json`. Names and schemas must not be frozen until they can
be checked against the author's complete text.

## Open Secure AI ecosystem relevance

If formally specified and independently testable, geometric witnesses could become an
additional deterministic guardrail and evaluation signal in a broader defensive AI
stack. They would complement model and harness findings; they would not turn
HERESY-SEC into a frontier model, EDR, SIEM, sandbox or autonomous response system.

No affiliation with or endorsement by HERESY-GEOM's author, NVIDIA, the Open Secure
AI Alliance or any other external project is claimed.
