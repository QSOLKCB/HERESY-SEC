# `heresy-geom.profile/v1`

## Status and scope

This is the normative implementation profile used by HERESY-SEC v0.2.0. It turns the
architectural requirements in the independently authored HERESY-GEOM paper into exact
bytes, arithmetic and failure behavior.

The profile is an implementation by the HERESY-SEC project, not an
author-certified reference implementation. It deliberately resolves choices that the
paper leaves open. Any change to those choices requires a new profile, fixture-set or
policy version and therefore a different policy identity.

Inputs remain untrusted descriptions. Graph construction and verification perform no
described file, process, network, model, tool or system action.

## Policy contract

Geometry is enabled only by `heresy-sec.policy/v2`. Every field is required:

```json
{
  "geometry": {
    "module": "heresy-geom",
    "version": "1",
    "fixture_set": "heresy-geom-conformance/v1",
    "window": 16,
    "quantize": {"scale": 16, "mode": "FLOOR"},
    "max_forman_abs": 64,
    "max_spectral_l2_delta": 4096,
    "epsilon_P": 1,
    "forbid_cycles": [],
    "require_delta_P": true
  }
}
```

Unknown or missing fields fail closed. Bounds are:

| Field | Exact domain |
| --- | --- |
| `window` | integer `1..32` |
| `quantize.scale` | integer `1..64` |
| `quantize.mode` | literal `FLOOR` |
| `max_forman_abs` | integer `0..1000000` |
| `max_spectral_l2_delta` | integer `0..1000000000` |
| `epsilon_P` | integer `1..4` |
| `forbid_cycles` | at most 16 patterns, each 1–8 labels |
| `require_delta_P` | exact boolean |

Cycle labels are lower-case `service.operation` identifiers. Rotationally equivalent
patterns are canonicalized and duplicates are rejected. The fixture-set identifier is
part of the policy hash preimage.

## Windows and graph construction

Actions retain their explicit, strictly increasing sequence. Consecutive, nonoverlapping
windows contain at most `geometry.window` actions.

The paper specifies resource vertices but does not define both endpoints of an action
edge. This profile resolves that gap with a bipartite directed multigraph:

- an actor vertex commits `agent_id` and `workload_id`;
- a resource vertex commits `service`, canonical target description and IPC slot when
  applicable;
- each action becomes one ordered edge committing sequence, action ID, service,
  operation, label and requested authority;
- `file.read`, `ipc.read`, `ipc.recv`, `model.recv`, `network.download`,
  `network.recv`, `network.receive` and `tool.read` point resource → actor;
- every other operation points actor → resource.

Vertex and edge descriptors receive separate domain-separated SHA-256 identities.
Vertices sort by hash; edges sort by `(sequence, edge_sha256)`. Parallel edges retain
multiplicity. Graph construction reads only normalized actions already captured by the
classical engine.

## Forman curvature

All edge weights are exactly one. For each edge `e = (u, v)`:

```text
forman(e) = 4 - degree(u) - degree(v)
quantized_forman(e) = forman(e) * quantize.scale
```

Parallel edges contribute independently to both degrees. A self-loop, if a future
contract can produce one, contributes two to its vertex degree. An edge trips the
curvature threshold when `abs(forman) > max_forman_abs`.

There is no Ollivier–Ricci path in profile v1.

## Spectral fingerprint

The projection is an undirected multigraph Laplacian. Each non-loop edge contributes
one to both endpoint degrees and `-1` to both symmetric off-diagonal entries. Loops are
ignored in this projection.

The runtime computes the monic characteristic polynomial over exact integers using
Faddeev–LeVerrier, square-free factors it over exact rational numbers, builds Sturm
sequences and isolates every real root. Laplacian roots are bounded by twice the
maximum degree. Each eigenvalue is stored as:

```text
floor(eigenvalue * quantize.scale)
```

No floating-point value enters an identity. Characteristic coefficients are stored as
decimal strings so arbitrarily large exact intermediate integers do not violate the
canonical safe-integer contract.

The spectral change is the integer square root of the sum of squared differences.
When window spectra have different lengths, zeros are prepended to the shorter vector.
The first window compares against the empty spectrum.

## Authority holonomy and `delta_P`

Requested authorities map to `Z2^4` masks:

| Authority | Mask |
| --- | ---: |
| `SIM_ONLY` | 0 |
| `READ_ONLY_EXTERNAL` | 1 |
| `WORKSPACE_WRITE` | 2 |
| `NETWORK` | 4 |
| `CONTROLLED_EXECUTION` | 8 |

The transition group operation is XOR and distance is Hamming weight. Each connected
component starts from the lexically smallest vertex with potential zero. A deterministic
breadth-first traversal assigns potentials. Every incompatible already-assigned
endpoint produces a residual mask.

`delta_P` is one when the maximum residual Hamming weight is at least `epsilon_P`;
otherwise it is zero. If `require_delta_P` is true, each residual is a `DISCHARGE`
`PRIVILEGE_PENROSE_LOOP`. If false, it is a `GAP_LIFT`, which prevents allow and
requires review.

## Impossible-configuration registry

Every obstruction commits its type, integer residual, resolve mode and contributing
edge identities.

| Type | Detector | Mode |
| --- | --- | --- |
| `PRIVILEGE_PENROSE_LOOP` | nonzero authority holonomy residual | `DISCHARGE` or `GAP_LIFT` |
| `FORBIDDEN_POLICY_CYCLE` | exact directed label cycle listed by policy | `DISCHARGE` |
| `EGRESS_STAIRCASE` | a file read followed by egress from the same agent | `GAP_LIFT` |
| `TRIDENT_TAINT_FORK` | one actor uses read-external, workspace-write and network masks across at least three directed targets | `GAP_LIFT` |
| `CRATE_LOG_OCCLUSION` | same target has non-denied, denied, non-denied ordering | `DISCHARGE` |
| `IPC_CARDINALITY_INVALID` | missing or out-of-range IPC slot | `DISCHARGE` |
| `FORMAN_THRESHOLD_TRIP` | curvature ceiling exceeded | `DISCHARGE` |
| `SPECTRAL_DELTA_TRIP` | spectral-change ceiling exceeded | `DISCHARGE` |

Cycle search is capped at 100,000 deterministic traversal steps. Exceeding the cap is a
controlled failure, not a partial result. `ATLAS_ONLY` is reserved by the architecture
but is not emitted by profile v1.

Any `DISCHARGE` makes the geometry result `DENY`. Otherwise any obstruction makes it
`REVIEW`; an empty registry makes it `ALLOW`.

## Evidence atoms and commitments

Each window emits a self-hashed evidence manifest containing atom-addressable
references for:

- policy identity;
- event range;
- raw capture hashes;
- classical decision hashes;
- each matched classical rule/action pair;
- action graph, curvature, spectral, holonomy and registry identities.

`N_missing` is zero in constructed output. Verification rebuilds the expected manifest
from captured bytes and rejects any missing, added, reordered or changed atom even if
an attacker also rebuilds the outer run manifest.

The geometry commitment binds the graph, curvature, spectral, holonomy, registry and
evidence-manifest identities plus `delta_P` and the geometry effect. A geometric receipt
then binds the commitment and decision to the head classical receipt, event range and
previous geometric receipt.

## Shadow Guard and decision precedence

Shadow Guard begins armed at the start of a run. A classical `DENY`, geometry `DENY`,
or geometry `REVIEW` trips the fuse. Once disarmed, a later would-be allow becomes
`DENY`.

Rearm is possible only when the first event in a later window is a classically allowed:

```text
service = "system"
operation = "rearm"
target = "shadow-guard"
```

The same window must also pass classical and geometry revalidation. A missing, denied
or misplaced rearm action cannot silently restore the fuse.

A load-bearing allow exists only when:

```text
shadow_guard_armed
and delta_P == 0
and classical_effect == ALLOW
and geometry_effect == ALLOW
and N_missing == 0
and curvature_ok
and spectral_ok
```

Classical evaluation always runs first. Geometry may preserve or tighten the result; it
cannot weaken a classical `DENY` or hard boundary.

## Artifacts and exact replay

Each window emits canonical JSON for the graph, curvature, spectrum, holonomy,
registry, evidence manifest, commitment, decision and receipt under
`geometry/NNNNNN/`. `geometry-event-log.jsonl` contains the geometric receipt chain.
The outer manifest commits every byte.

Verification reconstructs the complete versioned semantic artifact set. Exact replay
also requires the same implementation source-bundle identity. Added files, missing
files, changed canonical bytes, source changes or lineage changes fail closed.

## Conformance battery and known specification gap

The repository implements the eight tests actually defined by the supplied paper:

1. bit-identical graph/geometry replay;
2. Forman fixture values;
3. path and cycle Laplacian spectra;
4. authority-flip denial;
5. no silent Shadow Guard rearm;
6. missing-atom rejection;
7. all four named registry obstruction families with stable residuals;
8. curvature tamper rejection.

The paper twice says T1–T10 form the minimum battery but enumerates only T1–T8. Profile
v1 does not invent two unstated tests. Any later authoritative T9/T10 definitions
require named fixtures and a versioned compatibility decision.
