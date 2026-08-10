# YAML Doctoral Qualifying Examination

## Formal Semantics, Parser Differential Behaviour, Canonicalization, and Adversarial Edge Cases

> **Candidate instructions:** This examination is open-specification. Confidence without justification will be penalized.

This directory turns a deliberately cursed YAML doctoral examination into a **defensive parser-resilience corpus** for HERESY-SEC. Its purpose is to expose unsafe assumptions in configuration ingestion, parser upgrades, schema migration, round-tripping and cross-language pipelines before those assumptions reach production.

The corpus exercises scanner, parser, composer, resolver, constructor and dumper boundaries; YAML 1.1/1.2 schema drift; duplicate and host-language key collisions; anchors, aliases and merges; Unicode and line-ending edge cases; multi-document streams; explicit tags; round-trip degradation; and parser-specific behaviour.

## Containment model

The canonical exam is intentionally stored as seven inert `.part` shards under `source/` rather than as an auto-discoverable `.yaml` fixture. `assemble.py` concatenates those bytes only after verifying every shard and the final SHA-256. It **does not parse YAML**.

This keeps the normal HERESY-SEC CI path dependency-free and avoids accidentally feeding the corpus to a loader merely because a test runner, editor, linter or fixture collector scans `*.yaml` files.

```sh
python adversarial/yaml-doctoral-qualifier/assemble.py
python adversarial/yaml-doctoral-qualifier/assemble.py --output /tmp/EXAM.yaml
```

The canonical assembled identity is pinned in `manifest.json`:

```text
sha256  fa440e63da4cad5943ed1df2a7b7be5c6d4dd69d885a2419ebd9ad6993751125
bytes   50695
lines   1381
```

## Defensive use

Treat the assembled exam as hostile input. Differential parser experiments should run in a disposable offline sandbox or container with explicit parser versions, no secrets, no production credentials, bounded CPU/memory/time, and no writable production paths.

Unsafe-loader examples in the exam are retained only as commented research prompts. HERESY-SEC CI must not execute `yaml.load`/unsafe loaders, custom Python object constructors, resource-expansion demonstrations or candidate-generated payloads. The repository gate verifies corpus identity and containment, not the behaviour of third-party YAML libraries.

A useful downstream differential harness should record, for every case:

- parser and exact version;
- loader/schema configuration;
- success or exception class;
- resulting type and value;
- pipeline stage where behaviour diverged;
- key cardinality after host-language equality rules;
- alias/object identity where relevant;
- serialized output and any irreversible representation loss.

## Why this belongs in HERESY-SEC

HERESY-SEC is built around deterministic evidence, fail-closed boundaries and exact replay. YAML ambiguity is a good defensive regression target because two apparently equivalent ingestion stacks can construct different policy values from the same bytes. This corpus makes that class of failure concrete without adding a YAML parser to the trusted runtime.

In other words: **the parser must resit its PhD after every meaningful upgrade.**

## Safety boundary

This directory is not production configuration and is not an exploit runner. The static corpus may describe unsafe constructions for analysis, but executable reproduction belongs in a separately isolated research environment. The default HERESY-SEC runtime remains standard-library-only, offline and non-executing.
