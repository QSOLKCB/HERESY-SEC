# Determinism

## Included in identity

- exact captured policy bytes;
- exact ordered captured action bytes;
- normalized policy and action values;
- explicit producer, model and harness provenance;
- action sequence;
- policy v2 geometry module, fixture set, window, quantization, thresholds and cycle
  patterns;
- implementation source-bundle identity.

## Excluded hidden inputs

The runtime does not generate wall-clock timestamps, random nonces, UUIDs, hostnames,
absolute host paths, process IDs or network responses into identity.

An externally observed timestamp can be supplied as `observed_at`; because it is input,
it is hashed exactly like every other action field.

## Two complementary hashes

Each record has:

- a capture SHA-256 over the exact raw bytes; and
- an action SHA-256 over the normalized contract.

Whitespace changes therefore alter capture and run identity without altering the
normalized action identity. This preserves forensic fidelity while still supporting
semantic comparison.

## Replay

Replay first verifies the complete manifest and lineage. It then requires the exact
implementation source-bundle identity, re-evaluates every action, rebuilds every
classical and geometric receipt and summary, and compares canonical bytes. Replay does
not rewrite the run.

An implementation mismatch fails closed instead of claiming cross-version equality.

## Geometry determinism

For policy v2, geometry is a pure function of already captured normalized actions,
classical decisions and pinned policy fields. It performs no live-worker, filesystem,
network, process, model or clock lookup.

No floating-point value is computed or stored on the identity path. Forman curvature
is integer. Spectral characteristic polynomials, factorization and root isolation use
exact integer/rational arithmetic; only floor-quantized integer root buckets are
committed. Holonomy uses a finite XOR group and integer Hamming distance.

Each geometry window binds:

- its graph, curvature, spectrum, holonomy and registry;
- an atom-addressable evidence manifest;
- its geometry decision;
- the head classical receipt for the window;
- the previous geometry receipt.

Any changed captured byte, policy field, action order, matched rule, evidence atom,
geometry object or receipt link changes the reconstruction or fails verification.

## Deterministic archives

Archives use lexical path order, `ZIP_STORED`, the fixed DOS epoch, fixed Unix file
permissions, UTF-8 names, empty comments and no host-specific extra fields.
