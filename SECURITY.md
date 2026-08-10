# Security policy

Please report suspected vulnerabilities privately through the repository owner's
preferred GitHub security-reporting channel when available. Do not include live
credentials, private incident artifacts or exploit payloads in a public issue.

HERESY-SEC v0.3.0 is an experimental defensive evidence and deterministic geometry
engine. Its outputs do not replace professional incident response, operating-system
isolation or authenticated audit infrastructure. Geometry witnesses evaluate captured
descriptions; they neither execute actions nor prove that an attack occurred.

Profile v2 policy maps and thresholds are security-critical configuration. Treat a
weight map change, window change, fixture-set change or threshold change as a reviewed
policy release. Unknown fields, missing weighted labels and any learning mode fail
closed.

## Adversarial parser corpora

Static adversarial corpora under `adversarial/` are defensive regression material, not
trusted configuration. They may describe unsafe parser constructions, ambiguous scalar
semantics, recursive aliases or resource-expansion scenarios for analysis. Default CI
must verify their byte identity and containment without executing unsafe loaders,
custom object constructors or candidate-generated payloads.

Any live parser-differential work derived from those corpora should run in a disposable
offline sandbox with explicit dependency versions, no credentials, bounded CPU/memory/
time and no writable production paths. The normal HERESY-SEC runtime remains
standard-library-only, offline and non-executing.
