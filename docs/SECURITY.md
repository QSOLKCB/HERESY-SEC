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
- unsafe output paths and symbolic links are rejected;
- existing non-empty run directories are preserved and rejected;
- missing, changed or undeclared run files fail verification;
- source-bundle changes fail exact replay.

## Non-properties

HERESY-SEC v0.1.0 is not:

- an operating-system sandbox;
- an identity provider;
- a digital-signature system;
- an antivirus, EDR or network sensor;
- a model safety classifier;
- a vulnerability proof system;
- an autonomous responder.

Adapters that later observe real systems must maintain their own containment and least
privilege. Translating an event into HERESY-SEC does not make the event safe.

