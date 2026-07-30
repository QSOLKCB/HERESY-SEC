# HERESY-GEOM status and attribution

## Status

HERESY-SEC v0.2.0 implements the versioned
[`heresy-geom.profile/v1`](HERESY_GEOM_PROFILE.md) contract.

The implementation is derived from **HERESY-GEOM — A Deterministic Geometric Upgrade
Architecture for HERESY-SEC**, an academic architectural specification supplied to the
project and attributed to **DeltaKingZero / Dr. John Robitaille**, dated
**2026-07-27 UTC**.

The paper says it builds on the public `multimodalas/HERESY-SEC` determinism contract
without claiming ownership of that project. The maintained HERESY-SEC project now
lives at [`QSOLKCB/HERESY-SEC`](https://github.com/QSOLKCB/HERESY-SEC).

No author endorsement, certification, affiliation or ownership is claimed. The paper
has not been added to this repository because redistribution permission was not
provided. This implementation cites and attributes its architectural source while
publishing independently reviewable code, fixtures and profile rules.

## What is implemented

Policy v2 adds a bounded, standard-library-only geometry path:

- canonical directed action multigraphs;
- pinned integer Forman curvature;
- exact integer characteristic polynomials and Sturm-isolated, floor-quantized
  Laplacian spectra;
- authority-chart holonomy and `delta_P`;
- Shadow Guard fuse, trip, explicit rearm and revalidation;
- atom-addressable evidence and matched-rule references;
- typed impossible-configuration witnesses;
- domain-separated geometric commitments and forward-only receipts;
- full manifest verification, inspection and exact replay;
- the eight falsifiable tests actually defined in the paper.

Geometry runs after the existing hard boundaries and classical policy rules. It can
keep a result unchanged or make it stricter. It cannot turn a classical denial into
review or allow.

## Why this is an implementation profile

The paper is an architecture, not a byte-complete interoperability standard. It leaves
several choices open, including:

- complete graph endpoint and resource canonicalization rules;
- the fixed operation alphabet and edge orientation;
- exact Forman constants and parallel/self-loop behavior;
- directed versus undirected spectral mode and the large-window algorithm cutoff;
- authority-state lattice encoding and transition composition;
- detector algorithms and exact residual meanings for each registry class;
- which failures map to `AtlasOnly`, `GapLift` or `Discharge`;
- Shadow Guard rearm placement;
- canonical object schemas and domain-separation strings.

Calling one arbitrary resolution “the specification” would make replay claims
ambiguous. `heresy-geom.profile/v1` therefore pins every choice, bound and artifact
shape that affects identity. The profile name and fixture-set version are hashed in
policy v2.

## Specification inconsistency

Sections 14 and 18 say T1–T10 form the minimum battery. The document lists and defines
only T1 through T8. HERESY-SEC v0.2.0 implements all eight defined tests and records the
gap rather than inventing T9 or T10.

## Deliberate omissions

Profile v1 does not implement:

- Ollivier–Ricci curvature;
- floating-point spectral solvers or power iteration;
- policy-specified edge weights;
- regular-expression path automata;
- live-worker, host, filesystem or network observation;
- SPECTRAL sonification;
- a frontier model, EDR, SIEM, sandbox or autonomous response path;
- author-certified HERESY-GEOM conformance;
- the doctrinal KR-MPGM vocabulary as additional runtime state beyond the concrete
  graph, fuse, holonomy, resolution and window primitives.

These omissions keep the implementation falsifiable and within HERESY-SEC's small,
offline runtime boundary.

## Open Secure AI ecosystem relevance

The geometry layer can contribute replay-stable guardrail evidence beneath open and
closed forensic models. It gives a global action shape an auditable identity and makes
inconsistent authority closure visible without trusting model prose.

HERESY-SEC remains independent. It does not claim Open Secure AI Alliance membership,
NVIDIA endorsement or an accepted contribution.
