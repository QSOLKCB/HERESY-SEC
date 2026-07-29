# Policy format

## Top-level contract

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

## Boundaries

| Field | Meaning | Default |
| --- | --- | --- |
| `allowed_authorities` | Requested authority vocabulary | `["SIM_ONLY"]` |
| `max_parameter_bytes` | Canonical parameter JSON limit | `16384` |
| `max_ipc_slots` | Exclusive upper IPC slot bound | `32` |
| `network_enabled` | Whether network descriptions may pass | `false` |
| `allowed_network_schemes` | Exact lower-case schemes | `["https"]` |
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

