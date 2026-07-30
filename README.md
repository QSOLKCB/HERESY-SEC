# HERESY-SEC

**Deterministic policy, dual-window geometric evidence and exact replay for AI-agent actions.**

[![License](https://img.shields.io/badge/license-MPL--2.0-blue?style=flat-square)](LICENSE)
[![CI](https://github.com/QSOLKCB/HERESY-SEC/actions/workflows/ci.yml/badge.svg)](https://github.com/QSOLKCB/HERESY-SEC/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)
![Runtime](https://img.shields.io/badge/runtime-standard%20library-green?style=flat-square)
![Network](https://img.shields.io/badge/default%20network-none-green?style=flat-square)
![Bloat](https://img.shields.io/badge/infrastructure-is%20not%20a%20personality-red?style=flat-square)

> Small is inspectable. Proof beats promises. Infrastructure is not a personality.

HERESY-SEC is a compact, offline policy and evidence engine for proposed or observed
AI-agent actions. It preserves the original input bytes, normalizes strict JSON,
enforces classical security boundaries, emits hash-chained decisions, commits every
artifact to a manifest and reproduces the result through exact replay.

The canonical project home is
[`QSOLKCB/HERESY-SEC`](https://github.com/QSOLKCB/HERESY-SEC). The deterministic
identity and replay architecture is derived from
[QSOLAI](https://github.com/QSOLKCB/QSOLAI) and specialized for security telemetry.

## What v0.3.0 implements

HERESY-SEC v0.3.0 retains the complete v0.2.0 engine and adds the indivisible
`heresy-geom.profile/v2` **Forman Resolution Package**:

- Python 3.11+ standard-library-only runtime;
- strict canonical JSON and domain-separated SHA-256 identities;
- deterministic `ALLOW`, `DENY` and `REVIEW`;
- hard authority, network, process, file, IPC and parameter-size boundaries;
- exact capture, manifest verification, forward receipt chains and replay;
- a frozen compatibility path for `heresy-geom.profile/v1`;
- dual rolling geometry windows: short, long and policy-pinned stride;
- independent short/long Forman, spectral and holonomy evidence;
- unweighted or policy-weighted integer Forman curvature;
- both per-edge absolute and whole-window L1 curvature thresholds;
- mandatory Forman + spectral + holonomy companion atoms;
- a bundle digest binding both windows and the geometry manifest;
- fail-closed missing weight, unknown field, unsupported mode and learning rejection;
- Shadow Guard rearm only after classical and complete geometric revalidation;
- T2a–T2g fixtures for every resolved Forman limit.

The engine does **not** execute an action, inspect a live host, call a model, train a
detector, infer policy weights, discover novel attacks by itself or replace an
EDR/SIEM. Replay-stable anomaly witnessing is in scope. Adaptive anomaly learning is
not.

## Profiles

| Profile | Status | Window model | Forman model |
| --- | --- | --- | --- |
| `heresy-geom.profile/v1` | Frozen compatibility contract | One non-overlapping window | Unweighted integer curvature |
| `heresy-geom.profile/v2` | v0.3.0 Forman resolution | Short + long rolling windows with pinned stride | Unweighted or policy-weighted integer curvature |

Profile v2 is intentionally indivisible. A policy cannot enable weighted Forman while
omitting companion evidence, the L1 threshold, dual windows or the
`learning = forbidden` declaration.

The normative profile is documented in
[`docs/HERESY_GEOM_PROFILE_V2.md`](docs/HERESY_GEOM_PROFILE_V2.md). Profile v1 remains
documented in [`docs/HERESY_GEOM_PROFILE.md`](docs/HERESY_GEOM_PROFILE.md).

## Quick start

No package installation is required:

```sh
python -m heresy_sec selftest
python -m heresy_sec init demo
python -m heresy_sec run demo/action.json \
  --policy demo/policy.json \
  --runs-dir runs
```

Run the v0.3.0 dual-window example:

```sh
python -m heresy_sec monitor examples/forman_resolve/events.jsonl \
  --policy examples/forman_resolve/policy.json \
  --runs-dir runs \
  --run-name forman-resolve

python -m heresy_sec inspect runs/forman-resolve
python -m heresy_sec verify runs/forman-resolve
python -m heresy_sec replay runs/forman-resolve
```

Build the deterministic zipapp:

```sh
python scripts/build_zipapp.py
python scripts/verify_size.py dist/heresy_sec.pyz
python dist/heresy_sec.pyz selftest
```

## Profile-v2 policy block

```json
{
  "module": "heresy-geom",
  "version": "2",
  "fixture_set": "heresy-geom-conformance/v2",
  "window": {"short": 4, "long": 16, "stride": 4},
  "quantize": {"scale": 16, "mode": "FLOOR"},
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

Weighted mode uses a complete policy map from lower-case `service.operation` labels to
positive integers. An encountered label without a pinned weight fails closed; there is
no implicit default.

## Pinned integer Forman profile

For an edge `e = (u,v)` with positive integer weight `w(e)`, define weighted degree as
the sum of incident edge weights, with loops counted twice. HERESY-SEC pins:

```text
kappa_F(e) = 4*w(e) - d_w(u) - d_w(v)
```

Parallel edges count with multiplicity. In unweighted mode every edge has weight one,
so this reduces exactly to the frozen v1 expression:

```text
kappa_F(e) = 4 - deg(u) - deg(v)
```

Both bounds are mandatory:

```text
for every edge: abs(kappa_F(e)) <= max_abs
sum over window: abs(kappa_F(e)) <= max_window_l1
```

Either failure creates `FORMAN_THRESHOLD_TRIP` and prevents
`load_bearing_allow`.

## Normative conjunction

```text
forman_ok    = short_forman_ok and long_forman_ok
spectral_ok  = short_spectral_ok and long_spectral_ok
holonomy_ok  = short_delta_P == 0 and long_delta_P == 0
companion_ok = N_missing == 0

geom_ok = forman_ok and spectral_ok and holonomy_ok
          and companion_ok and registry_effect == ALLOW

load_bearing_allow = classical_effect == ALLOW
                     and geom_ok
                     and delta_P == 0
                     and shadow_guard_armed
                     and N_missing == 0
                     and final_effect == ALLOW
```

Geometry can only preserve or tighten a classical decision. It cannot weaken a
classical `DENY`.

## Profile-v2 artifacts

Each geometry bundle has one top-level decision plane and two sensor planes:

```text
geometry-event-log.jsonl
geometry/000000/manifest-geometry.json
geometry/000000/bundle.json
geometry/000000/impossible-configurations.json
geometry/000000/evidence-manifest.json
geometry/000000/commitment.json
geometry/000000/decision.json
geometry/000000/receipt.json
geometry/000000/short/{action-graph,curvature,spectral,holonomy,impossible-configurations}.json
geometry/000000/long/{action-graph,curvature,spectral,holonomy,impossible-configurations}.json
```

The bundle commits to `K_short`, `K_long`, `S_short`, `S_long`, both holonomy
digests, `delta_P` and the pinned geometry manifest. Exact reconstruction is required
during verification and replay.

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

Exit status `0` means an allowed or successful non-decision command, `3` means
`DENIED`, `4` means `REVIEW_REQUIRED`, and `2` means invalid input or controlled
failure. Errors are canonical JSON on standard error.

## Determinism contract

For one source bundle:

```text
same captured policy bytes
+ same ordered captured action bytes
+ same normalization and policy contracts
= same classical decisions and receipt chain
+ same short and long geometry windows
+ same companion atoms and bundle hashes
+ same geometric decision and receipt chain
+ same summary, manifest and archive bytes
```

No wall clock, hostname, process ID, random value, model response, live worker or
network lookup enters canonical identity.

## Provenance and scope

HERESY-GEOM is an independently authored academic architecture attributed to
DeltaKingZero / Dr. John Robitaille. The v0.3.0 parallel Forman-resolution package was
supplied to this project by **3n0ch**. HERESY-SEC implements an independently
reviewable profile and does not claim author certification, ownership, endorsement or
affiliation.

The symbolic package header supplied with the proposal is preserved in the normative
document as provenance, but it is not used as a security predicate because its symbols
were not defined as executable policy semantics.

## Quality gates

```sh
python -m compileall -q heresy_sec tests scripts
python -m unittest discover -s tests -v
python -m heresy_sec selftest
python scripts/audit_architecture.py
python scripts/audit_network.py
python scripts/build_zipapp.py
python scripts/verify_size.py dist/heresy_sec.pyz
python dist/heresy_sec.pyz selftest
```

## Licence and lineage

HERESY-SEC is licensed under the [Mozilla Public License 2.0](LICENSE). See
[SOURCE_LINEAGE](docs/SOURCE_LINEAGE.md), [NOTICE](NOTICE.md) and
[SECURITY](SECURITY.md).
