# HERESY-SEC

**Deterministic security receipts and exact replay for AI-agent actions.**

[![License](https://img.shields.io/badge/license-MPL--2.0-blue?style=flat-square)](LICENSE)
[![CI](https://github.com/QSOLKCB/HERESY-SEC/actions/workflows/ci.yml/badge.svg)](https://github.com/QSOLKCB/HERESY-SEC/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)
![Runtime](https://img.shields.io/badge/runtime-standard%20library-green?style=flat-square)
![Network](https://img.shields.io/badge/default%20network-none-green?style=flat-square)
![Bloat](https://img.shields.io/badge/infrastructure-is%20not%20a%20personality-red?style=flat-square)

> Small is inspectable. Proof beats promises. Infrastructure is not a personality.

HERESY-SEC is a compact, offline policy and evidence engine for actions proposed or
observed in AI-agent systems. It captures the original bytes, normalizes strict JSON,
checks explicit boundaries, issues hash-chained decisions, commits every artifact to a
manifest, and reproduces the result through exact replay.

The canonical project home is
[`QSOLKCB/HERESY-SEC`](https://github.com/QSOLKCB/HERESY-SEC).
It is built from the deterministic design principles of
[QSOLAI](https://github.com/QSOLKCB/QSOLAI), specialized for security telemetry.
Open-weight and closed models are both supported as provenance declarations; neither
is trusted merely because of its licensing model.

## What v0.1.0 actually implements

- Python 3.11+ standard-library-only runtime;
- one-action JSON and ordered JSONL monitoring modes;
- exact preservation of each input record before parsing;
- strict canonical JSON with duplicate-key, float, cycle and unsafe-integer rejection;
- domain-separated SHA-256 identities for actions, policies, decisions, receipts,
  runs, manifests and the implementation source bundle;
- deterministic `ALLOW`, `DENY` and `REVIEW` decisions;
- hard authority, network, process, file, IPC-slot and parameter-size boundaries;
- conservative rule conflict handling: `DENY` wins an equal-priority conflict;
- model/harness/workload provenance without vendor preference;
- forward-only receipt chains and exact artifact manifests;
- verification, inspection, deterministic archives and byte-exact replay;
- runnable examples, a standard-library test suite, architecture/network audits and a
  deterministic zipapp build.

HERESY-SEC does **not** call a model, inspect a live host, execute an agent action,
replace an EDR/SIEM, detect novel attacks by itself, or prove that a SHA-256 receipt
was signed by a particular person. Those are separate capabilities and future adapter
work must preserve these boundaries.

## Quick start

No package installation is required:

```sh
python -m heresy_sec selftest
python -m heresy_sec init demo
python -m heresy_sec run demo/action.json \
  --policy demo/policy.json \
  --runs-dir runs
```

Verify and replay the emitted run:

```sh
python -m heresy_sec verify runs/<run-name>
python -m heresy_sec replay runs/<run-name>
python -m heresy_sec inspect runs/<run-name>
```

Evaluate an ordered stream:

```sh
python -m heresy_sec monitor demo/events.jsonl \
  --policy demo/policy.json \
  --runs-dir runs
```

Build the self-contained artifact:

```sh
python scripts/build_zipapp.py
python scripts/verify_size.py dist/heresy_sec.pyz
python dist/heresy_sec.pyz selftest
```

## CLI

```text
heresy-sec init [DIRECTORY]
heresy-sec validate ACTION --policy POLICY
heresy-sec run ACTION --policy POLICY [--runs-dir RUNS] [--run-name NAME]
heresy-sec monitor EVENTS.jsonl --policy POLICY [--runs-dir RUNS] [--run-name NAME]
heresy-sec verify RUN
heresy-sec replay RUN
heresy-sec inspect RUN
heresy-sec pack RUN [--output ARCHIVE]
heresy-sec selftest
heresy-sec size [ARTIFACT]
```

Exit status `0` means an allowed or successful non-decision command, `3` means a run
completed with `DENIED`, `4` means `REVIEW_REQUIRED`, and `2` means invalid input or a
controlled failure. Errors are canonical JSON on standard error.

## Security event contract

Each action names its producer, model class, harness, requested authority, service,
operation and target. Model and harness digests are optional in v0.1.0 because closed
providers and development harnesses may not expose them; absence remains explicit.

```json
{
  "schema": "heresy-sec.action/v1",
  "action_id": "blocked-network-upload",
  "sequence": 0,
  "producer": {
    "schema": "heresy-sec.producer/v1",
    "agent_id": "forensic-agent",
    "workload_id": null,
    "model_id": "local/frontier-forensics",
    "model_kind": "OPEN_WEIGHT",
    "model_digest": null,
    "harness_id": "incident-harness/v1",
    "harness_digest": null
  },
  "observed_at": null,
  "service": "network",
  "operation": "upload",
  "target": "https://unapproved.example/evidence",
  "parameters": {"bytes": 4096, "method": "POST"},
  "requested_authority": "NETWORK",
  "slot": null,
  "context": {"incident": "synthetic-example"}
}
```

The engine never trusts a caller-provided hash. It computes both the exact capture hash
and the normalized action identity itself. See [policy format](docs/POLICY_FORMAT.md).

## Run artifacts

```text
policy.raw                 policy.json
implementation.json       summary.json
captures/000000.raw        actions/000000.json
decisions/000000.json      receipts/000000.json
event-log.jsonl            README_ORIGIN.txt
manifest.json
```

The manifest commits to every other file by exact byte length and SHA-256. Receipts
link capture, action, policy and decision identities to the previous receipt. Changing
whitespace in captured input changes the run identity while leaving its normalized
action identity unchanged.

## Determinism contract

For one source-bundle version:

```text
same captured policy bytes
+ same ordered captured action bytes
+ same normalization and policy contracts
= same normalized actions
+ same decisions
+ same receipt chain
+ same summary
+ same manifest inputs
+ same deterministic archive bytes
```

No wall clock, hostname, process ID, random value or hidden network response enters
canonical identity. See [determinism](docs/DETERMINISM.md).

## Open Secure AI ecosystem path

NVIDIA's July 2026 announcement for the
[Open Secure AI Alliance](https://blogs.nvidia.com/blog/open-secure-ai-alliance/)
describes an open defense stack spanning identity, permissions, harnesses, guardrails,
logs and evaluation, with both open and closed frontier models.

HERESY-SEC's plausible contribution is not another frontier model. It is a small,
vendor-neutral **evidence and replay plane** beneath them:

| Open defense-stack need | HERESY-SEC foundation |
| --- | --- |
| Identity | Stable agent ID plus optional workload identity |
| Permissions | Canonical policy packs and requested authority |
| Harness traceability | Model and harness provenance fields |
| Guardrails | Deterministic hard boundaries before rules |
| Logs | Raw captures, decisions, receipts and manifests |
| Evaluation | Exact replay and portable incident fixtures |

The project is independent and is not claiming Alliance membership, endorsement or an
accepted contribution. The concrete interoperability roadmap is in
[Open Secure AI Alliance contribution path](docs/OPEN_SECURE_AI_ALLIANCE.md).

## HERESY-GEOM extension boundary

A supplied 27 July 2026 title-page screenshot identifies **HERESY-GEOM**, attributed
to DeltaKingZero / Dr. John Robitaille, as an independent deterministic geometric
upgrade architecture for HERESY-SEC. It names action graphs, discrete curvature,
holonomy gates, shadow-guard integrity, atom-addressable policy objects, an
impossible-configuration registry and a KR-MPGM spine.

Those names are **not implemented claims** in v0.1.0. The complete specification,
formal definitions and falsification vectors were not supplied with this repository,
so inventing their semantics would violate the project's replay-stable,
non-heuristic contract. The proposed integration boundary and the evidence required
before implementation are recorded in
[HERESY-GEOM integration notes](docs/HERESY_GEOM.md).

## Runnable examples

- [`file_integrity`](examples/file_integrity/) — permits a simulated in-workspace read;
- [`network_constraint`](examples/network_constraint/) — a hard network boundary
  overrides an apparent allow rule;
- [`process_boundary`](examples/process_boundary/) — rejects a process-launch proposal;
- [`ipc_slot_management`](examples/ipc_slot_management/) — rejects slot 32 from the
  fixed `0..31` range.

These examples evaluate structured descriptions. They do not touch the filesystem
targets, start processes or contact networks.

## Quality gates

```sh
python -m unittest discover -s tests -v
python -m heresy_sec selftest
python scripts/audit_architecture.py
python scripts/audit_network.py
python scripts/build_zipapp.py
python scripts/verify_size.py dist/heresy_sec.pyz
python dist/heresy_sec.pyz selftest
```

## Licence and lineage

HERESY-SEC is licensed under the [Mozilla Public License 2.0](LICENSE). The canonical
JSON, source-bundle identity, fail-closed artifact, deterministic archive and replay
architecture are derived from QSOLAI under the same licence. Details are recorded in
[SOURCE_LINEAGE](docs/SOURCE_LINEAGE.md) and [NOTICE](NOTICE.md).
