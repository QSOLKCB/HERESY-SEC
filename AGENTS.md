# HERESY-SEC agent rules

These rules apply to every file and future coding agent in this repository.

## Product identity

HERESY-SEC is a deterministic evidence, policy and replay engine for AI-agent security
events. Inputs are untrusted descriptions. The runtime never executes the described
file, network, process, tool or system action.

Do not turn the project into a browser frontend, cloud service, generic chatbot,
autonomous offensive tool or documentation-only receipt collection.

## Non-negotiable runtime architecture

- Python 3.11+ standard-library-only runtime.
- No direct network client, telemetry exporter, database server or model SDK.
- No `eval`, `exec`, pickle, hidden entropy or `shell=True`.
- No generated wall-clock or host value in canonical identity.
- No floats in identity-bearing structures.
- No custom cryptography.
- Existing non-empty output paths must be preserved and rejected.

## Determinism

- Capture exact bytes before parsing.
- Reject duplicate JSON keys, floats, cycles, unsafe integers and unexpected fields.
- Preserve ordered action streams and require explicit unique sequences.
- Use domain-separated SHA-256.
- Hard boundaries precede policy rules.
- Equal-priority conflicts resolve `DENY`, `REVIEW`, `ALLOW`, then lexical `rule_id`.
- Exact replay fails on any changed byte, lineage break or source-bundle mismatch.

## Claims

- SHA-256 receipts provide integrity, not signer authenticity.
- Model kind is provenance, not a trust verdict.
- HERESY-SEC is not an EDR, SIEM, sandbox, identity provider or frontier model.
- Do not claim Open Secure AI Alliance membership, endorsement or acceptance.
- Sonification is an alert representation, never evidence.

## Required checks

```sh
python -m unittest discover -s tests -v
python -m heresy_sec selftest
python scripts/audit_architecture.py
python scripts/audit_network.py
python scripts/build_zipapp.py
python scripts/verify_size.py dist/heresy_sec.pyz
python dist/heresy_sec.pyz selftest
```

