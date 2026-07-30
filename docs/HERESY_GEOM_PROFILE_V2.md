# HERESY-GEOM profile v2: Forman resolution package

**Profile:** `heresy-geom.profile/v2`  
**Fixture set:** `heresy-geom-conformance/v2`  
**Package lineage:** `heresy-geom.forman-resolve/v1`  
**HERESY-SEC release:** v0.3.0

## Status and provenance

This profile implements the parallel Forman-resolution package supplied by 3n0ch for
HERESY-SEC. It is an independently reviewable implementation profile and does not claim
author certification or endorsement.

The supplied header—`N(t) = 251 · κ ≤ √2−1 · 0 < τ < 1 · Substrate coherent`,
`Measure⁴ × Cut¹`, and `IREE · SGCF · MSTNC active`—is retained as provenance, not as
an executable security rule. The terms do not include sufficiently pinned units,
domains, transitions or byte-level semantics for deterministic policy evaluation.

## Compatibility boundary

`heresy-geom.profile/v1` remains frozen. Existing policy-v2 runs that pin geometry
module version `1` retain the v0.2.0 graph, curvature, window, artifact and replay
contract. Module version `2` selects this profile as one indivisible package.

The five resolutions cannot be enabled piecemeal:

1. Forman is accompanied by spectral and holonomy evidence.
2. Short and long windows are both mandatory.
3. Forman mode and its complete weight map are pinned.
4. Per-edge and window-L1 thresholds are both mandatory.
5. `learning` must be exactly `forbidden`.

Unknown or missing fields fail closed.

## Exact policy shape

```json
{
  "module": "heresy-geom",
  "version": "2",
  "fixture_set": "heresy-geom-conformance/v2",
  "window": {
    "short": 4,
    "long": 16,
    "stride": 4
  },
  "quantize": {
    "scale": 16,
    "mode": "FLOOR"
  },
  "forman": {
    "mode": "unweighted",
    "weight_map": {},
    "max_abs": 64,
    "max_window_l1": 512,
    "learning": "forbidden"
  },
  "max_spectral_l2_delta": 4096,
  "epsilon_P": 1,
  "forbid_cycles": [],
  "require_delta_P": true
}
```

The schedule must satisfy:

```text
1 ≤ stride ≤ short ≤ long ≤ 32
```

Windows end at deterministic stride boundaries. A final partial endpoint is emitted
when the stream length is not divisible by the stride. Short and long spectra maintain
independent previous-spectrum histories.

## Integer Forman profile

For each edge `e=(u,v)` with positive integer weight `w(e)`, define weighted degree as
the sum of incident weights. A loop contributes twice. Parallel edges retain
multiplicity.

```text
κ_F(e) = 4 w(e) − d_w(u) − d_w(v)
```

Unweighted mode sets every edge weight to one and therefore reduces exactly to the
profile-v1 formula:

```text
κ_F(e) = 4 − deg(u) − deg(v)
```

Weighted mode requires a non-empty policy map from canonical action labels such as
`file.read` to exact positive integers. Every observed label must be present. Missing
weights fail with `GEOMETRY_FORMAN_WEIGHT_MISSING`; there is no implicit default.

No floating-point value enters the identity path. Quantized Forman values are the exact
integer curvature multiplied by the pinned quantization scale.

## Threshold semantics

Both statistics are mandatory for both window roles:

```text
edge_abs_ok  ⇔  ∀e |κ_F(e)| ≤ max_abs
window_l1_ok ⇔  Σe |κ_F(e)| ≤ max_window_l1
forman_ok    ⇔  edge_abs_ok ∧ window_l1_ok
```

A failure of either statistic emits `FORMAN_THRESHOLD_TRIP` with a pinned
`threshold_kind` and forces registry `DENY`. Distributed curvature can therefore trip
the window-L1 bound even when no individual edge exceeds `max_abs`.

## Mandatory companion triple

For each short and long window, the evidence manifest must include:

```text
SHORT_FORMAN     LONG_FORMAN
SHORT_SPECTRAL   LONG_SPECTRAL
SHORT_HOLONOMY   LONG_HOLONOMY
```

The manifest computes `N_missing` from this required set. Forman evidence cannot stand
alone in a load-bearing allow.

## Bundle commitment

Each window emits `manifest-geometry.json` and `bundle.json`. The bundle commits to:

```text
K_short, K_long,
S_short, S_long,
H_short, H_long,
delta_P,
manifest_geometry_sha256
```

The profile includes holonomy digests explicitly in addition to the package shorthand
`(K_digest, S_digest, δ_P)` so every companion artifact is independently addressable
and replay-bound.

## Normative conjunction

```text
forman_ok   ⇔ short_forman_ok ∧ long_forman_ok
spectral_ok ⇔ short_spectral_ok ∧ long_spectral_ok
holonomy_ok ⇔ δ_P(short)=0 ∧ δ_P(long)=0
companion_ok ⇔ N_missing=0

geom_ok ⇔ forman_ok
       ∧ spectral_ok
       ∧ holonomy_ok
       ∧ companion_ok
       ∧ registry_effect=ALLOW

LoadBearingAllow ⇔ classical_effect=ALLOW
                 ∧ geom_ok
                 ∧ δ_P=0
                 ∧ shadow_guard_armed
                 ∧ N_missing=0
                 ∧ final_effect=ALLOW
```

Classical `DENY` is never weakened. Geometry can only preserve or tighten the
classical result.

## Shadow Guard

A geometry denial, review, failed companion check or failed conjunction trips the fuse.
Rearm requires an explicit allowed `system.rearm` action targeting `shadow-guard` as
the first newly admitted action at a stride boundary, followed by successful classical
and complete dual-window geometry revalidation. Silent rearm is impossible.

## Artifacts

Profile-v2 windows add role-specific artifacts:

```text
geometry/<index>/manifest-geometry.json
geometry/<index>/bundle.json
geometry/<index>/impossible-configurations.json
geometry/<index>/evidence-manifest.json
geometry/<index>/commitment.json
geometry/<index>/decision.json
geometry/<index>/receipt.json
geometry/<index>/short/action-graph.json
geometry/<index>/short/curvature.json
geometry/<index>/short/spectral.json
geometry/<index>/short/holonomy.json
geometry/<index>/short/impossible-configurations.json
geometry/<index>/long/action-graph.json
geometry/<index>/long/curvature.json
geometry/<index>/long/spectral.json
geometry/<index>/long/holonomy.json
geometry/<index>/long/impossible-configurations.json
```

Every artifact is canonical JSON, included in the run manifest and reconstructed during
verification and exact replay.

## Falsification battery

| ID | Requirement |
| --- | --- |
| T2a | Profile-v1 unweighted fixtures remain unchanged. |
| T2b | Weighted fixtures match the pinned integer weight map. |
| T2c | Short and long digests are bit-identical across runs and replay. |
| T2d | A single-edge absolute-curvature breach denies. |
| T2e | A distributed window-L1 breach denies without an edge breach. |
| T2f | Any `learning` value other than `forbidden` fails policy load. |
| T2g | Removing a Forman, spectral or holonomy companion artifact fails verification. |

An additional hostile-input test requires every weighted action label to have a pinned
weight.

## Residual risks

- Dual windows increase curvature work and duplicate bounded spectral/holonomy work.
- Weighted-mode quality depends on policy authors choosing defensible integer maps.
- Forman remains local; long-range structure remains the responsibility of spectral,
  holonomy and registry companions.
- Threshold calibration remains a policy and fixture responsibility, not an adaptive
  learner.

These are explicit profile constraints, not hidden heuristics.
