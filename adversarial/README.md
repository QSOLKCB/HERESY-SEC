# Defensive adversarial corpora

This directory contains static hostile-input regression material for HERESY-SEC. Corpora are evidence fixtures, not trusted configuration and not exploit runners.

## Corpora

- [`yaml-doctoral-qualifier/`](yaml-doctoral-qualifier/) — **YAML Doctoral Qualifying Examination: Formal Semantics, Parser Differential Behaviour, Canonicalization, and Adversarial Edge Cases.** A byte-pinned, inertly sharded corpus for testing YAML parser/schema drift, host-language key collisions, aliases/merges, duplicate handling, Unicode, line endings and round-trip loss.

Normal CI verifies corpus identity and containment using the Python standard library only. Live third-party parser experiments belong in disposable offline sandboxes with explicit versions and resource limits.
