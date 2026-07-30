# Technical specification

## Runtime boundary

HERESY-SEC v0.2.0 uses Python 3.11+ and the standard library. The runtime contains no
direct network client, model SDK, database, telemetry exporter, dynamic code execution,
pickle deserialization, hidden entropy source or `shell=True` path.

Input actions describe proposed or observed behavior. Evaluation performs no described
action.

## Processing sequence

1. Preserve the exact action and policy bytes.
2. Parse one UTF-8 JSON value with duplicate-key, float and non-finite rejection.
3. Normalize versioned action and policy contracts.
4. Compute domain-separated action and policy identities.
5. Apply hard boundary checks.
6. Match rules by descending priority.
7. Resolve equal-priority conflicts conservatively: `DENY`, then `REVIEW`, then `ALLOW`,
   then lexical `rule_id`.
8. Build a self-hashed decision.
9. Link the decision to the previous receipt.
10. For policy v2, partition the ordered stream into bounded windows.
11. Build each action graph, exact curvature and spectral records, holonomy residuals,
    registry witnesses and evidence atoms.
12. Apply the Shadow Guard fuse and link the geometric commitment and decision to both
    the classical and prior geometric receipts.
13. Commit all bytes to a self-hashed manifest.

## Rule semantics

Rules match service, operation, target prefix, agent ID and requested authority. Lists
are normalized as sorted sets. Rule order in source JSON does not affect the normalized
policy. Explicit priority and the fixed conflict order control selection.

Hard boundary failures always result in `DENY`; a matching `ALLOW` rule cannot override
them.

## Batch ordering

JSONL records retain input order. `sequence` values must be unique and supplied in
strictly ascending order. `action_id` values must be unique within one run.

Receipt indices are zero-based batch positions and are distinct from producer-supplied
action sequence values.

Geometry window indices are also zero-based. Windows are consecutive and
nonoverlapping. Their first and last producer-supplied sequences form the committed
event range.

## Identity

Hashes use:

```text
SHA-256(UTF8(domain) || NUL || canonical-json(value))
```

Raw capture hashes use ordinary SHA-256 over the exact input bytes. Domains are defined
in `heresy_sec/canonical.py`.

Geometry adds separate domains for vertices, edges, graphs, curvature, spectra,
holonomy, obstructions, event ranges, rule matches, evidence atoms/manifests,
commitments, decisions and receipts. Exact spectral polynomial coefficients are
serialized as decimal strings; quantized roots and residuals remain bounded canonical
integers.

## Geometry semantics

`heresy-sec.policy/v2` selects `heresy-geom.profile/v1`. It uses:

- a directed actor/resource multigraph from captured normalized actions;
- unweighted Forman curvature `4 - degree(u) - degree(v)`;
- the undirected multigraph combinatorial Laplacian;
- exact characteristic-polynomial arithmetic and Sturm root isolation;
- floor quantization at the policy scale;
- `Z2^4` XOR authority transitions with Hamming residuals;
- deterministic typed obstruction detectors;
- a one-bit Shadow Guard fuse with explicit logged rearm.

The complete bounds and ambiguity resolutions are normative in
[HERESY_GEOM_PROFILE](HERESY_GEOM_PROFILE.md).

## Artifact semantics

Policy v1 retains the v1 summary and classical artifact set. Policy v2 emits a v2
summary and nine canonical artifacts per geometry window, plus a geometric receipt
JSONL log. Verification reconstructs the exact artifact set, so an attacker cannot add
a file and merely rebuild the outer manifest.

Exact replay requires the source-bundle identity that created the run. The policy v1
schema remains accepted by v0.2.0, but a v0.1.0 run intentionally cannot claim exact
cross-version replay under a changed source bundle.

## File targets

File targets are safe relative POSIX descriptions. Absolute paths, backslashes, NULs,
empty segments, `.` and `..` are rejected. This lexical check is not a filesystem
sandbox and the engine does not open the target.

## Network targets

Network targets must be absolute URL-like strings with an allowed scheme and exact
host. User-info is rejected. The parser is intentionally small because the runtime
never opens the URL. Production adapters should validate their own richer endpoint
types before translating them into the common contract.
