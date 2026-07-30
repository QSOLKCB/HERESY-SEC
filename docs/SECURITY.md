# Security model

## Trust boundary

All action records, producer claims, model identifiers, harness identifiers, targets
and parameters are untrusted input. Model kind is provenance, not a trust score.

The policy file is also untrusted until it passes its strict contract. Policy identity
does not prove who authorized it.

## What SHA-256 receipts prove

Receipts can show:

- exact capture integrity;
- normalized action identity;
- policy and decision lineage;
- receipt order;
- post-capture tampering.

Unsigned receipts cannot show who produced or approved an action. Authenticated
provenance is explicitly deferred to reviewed standard integrations.

## Fail-closed properties

- unexpected contract fields are rejected;
- floats, duplicate keys, cycles and unsafe integers are rejected;
- hard boundaries override allow rules;
- geometry runs after hard boundaries and can only preserve or tighten their result;
- missing or changed geometry evidence fails reconstruction even when the outer
  manifest is rebuilt;
- a tripped Shadow Guard cannot silently rearm;
- geometry cycle search, windows and policy collections have deterministic bounds;
- unsafe output paths and symbolic links are rejected;
- existing non-empty run directories are preserved and rejected;
- missing, changed or undeclared run files fail verification;
- source-bundle changes fail exact replay.

## Non-properties

HERESY-SEC v0.2.0 is not:

- an operating-system sandbox;
- an identity provider;
- a digital-signature system;
- an antivirus, EDR or network sensor;
- a model safety classifier;
- a vulnerability proof system;
- an autonomous responder;
- an author-certified implementation of the independently authored HERESY-GEOM paper.

Adapters that later observe real systems must maintain their own containment and least
privilege. Translating an event into HERESY-SEC does not make the event safe.

## Geometry interpretation

Curvature, spectra, holonomy and registry results are deterministic policy evidence,
not probabilistic threat scores and not proof that an attack occurred. A geometric
allow means only that every predicate in the pinned profile passed for the captured
descriptions. It does not grant operating-system authority.

`GAP_LIFT` means additional evidence or review is required. `DISCHARGE` means denial.
SPECTRAL sonification, if added by a future adapter, remains an alert representation
and can never be evidence or authority.
