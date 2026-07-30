# Policy format

## Policy v1

```json
{
  "schema": "heresy-sec.policy/v1",
  "policy_id": "example-policy",
  "default_effect": "DENY",
  "boundaries": {},
  "rules": []
}
```

`default_effect` is `ALLOW`, `DENY` or `REVIEW`. Security deployments should normally
use `DENY`.

Policy v1 remains accepted and emits no geometry artifacts.

## Policy v2

Policy v2 has the same classical boundaries and rules plus one required exact geometry
object:

```json
{
  "schema": "heresy-sec.policy/v2",
  "policy_id": "geometry-policy",
  "default_effect": "DENY",
  "boundaries": {},
  "rules": [],
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

Every geometry field is required. Unknown fields, missing fields, unsupported module
or fixture-set versions, floats and out-of-range integers fail closed.

| Geometry field | Meaning |
| --- | --- |
| `module`, `version` | Exact implementation selector: `heresy-geom`, `1` |
| `fixture_set` | Exact conformance-vector selector |
| `window` | Consecutive action count, `1..32` |
| `quantize` | Integer scale `1..64` and literal `FLOOR` |
| `max_forman_abs` | Inclusive absolute-curvature ceiling |
| `max_spectral_l2_delta` | Inclusive integer spectral-change ceiling |
| `epsilon_P` | Holonomy Hamming threshold, `1..4` |
| `forbid_cycles` | Exact directed `service.operation` cycle patterns |
| `require_delta_P` | `true` discharges holonomy residuals; `false` requires review |

Cycle patterns contain 1–8 lower-case labels. At most 16 patterns are accepted.
Rotational duplicates are rejected. See the complete
[`heresy-geom.profile/v1`](HERESY_GEOM_PROFILE.md) contract.

## Boundaries

| Field | Meaning | Default |
| --- | --- | --- |
| `allowed_authorities` | Requested authority vocabulary | `["SIM_ONLY"]` |
| `max_parameter_bytes` | Canonical parameter JSON limit | `16384` |
| `max_ipc_slots` | Exclusive upper IPC slot bound | `32` |
| `network_enabled` | Whether network descriptions may pass | `false` |
| `allowed_network_schemes` | Exact lower-case RFC-style schemes | `["https"]` |
| `allowed_network_hosts` | Exact lower-case hosts | `[]` |
| `process_enabled` | Whether process descriptions may pass | `false` |
| `allowed_processes` | Exact process targets | `[]` |
| `file_target_prefixes` | Safe relative POSIX prefixes | `["workspace/"]` |

An empty host or process allowlist allows none.

## Rules

```json
{
  "schema": "heresy-sec.rule/v1",
  "rule_id": "allow-evidence-read",
  "priority": 100,
  "effect": "ALLOW",
  "services": ["file"],
  "operations": ["read"],
  "target_prefixes": ["workspace/evidence/"],
  "agent_ids": ["forensic-agent"],
  "authorities": ["SIM_ONLY"]
}
```

Omitted match lists default to `["*"]`. At equal priority a more conservative effect
wins: `DENY`, then `REVIEW`, then `ALLOW`. Lexical `rule_id` is the final tie-break.

## Hard boundary precedence

Rules cannot override:

- ungranted requested authority;
- parameter-size overflow;
- disabled or unlisted network endpoints;
- disabled or unlisted processes;
- unsafe or out-of-prefix file targets;
- missing or out-of-range IPC slots.

Matched rule IDs remain in the decision trace even when a boundary forces denial.

For policy v2, classical evaluation still occurs first. A geometry window then reduces
its classical and geometric results using the same conservative order: `DENY`,
`REVIEW`, `ALLOW`. Geometry can never weaken a hard-boundary denial. A Shadow Guard
fuse can additionally turn a later would-be allow into denial until an explicit,
classically allowed rearm action begins a successfully revalidated window.
