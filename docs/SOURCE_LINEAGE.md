# Source lineage

The canonical project home is
[`QSOLKCB/HERESY-SEC`](https://github.com/QSOLKCB/HERESY-SEC).
HERESY-SEC is a downstream, security-specific implementation informed by
[QSOLAI](https://github.com/QSOLKCB/QSOLAI).

The following architectural elements are adapted from QSOLAI:

- strict canonical JSON;
- domain-separated SHA-256 identities;
- exact preservation of untrusted input before normalization;
- deterministic post-capture processing;
- self-hashed implementation identity;
- fail-closed run directories and manifests;
- exact replay;
- deterministic `ZIP_STORED` archives;
- architecture, network and size audits.

HERESY-SEC introduces its own action, producer, policy, boundary, decision and receipt
contracts plus security-specific CLI, examples and tests.

Both projects use the Mozilla Public License 2.0. This repository preserves the
relevant notices and does not claim that QSOLAI itself is an intrusion-detection
system.

## Repository relocation

The first complete HERESY-SEC v0.1.0 implementation was prepared for
[`multimodalas/HERESY-SEC`](https://github.com/multimodalas/HERESY-SEC) and published
for review on 30 July 2026. At the project owner's request, it was then rebuilt in the
QSOLKCB organization so the security project and its CI live with the rest of the
QSOL work.

The relocation changes the project home, not the deterministic contracts or licence.
The earlier public history remains provenance; this repository is the maintained
upstream.

## Independent HERESY-GEOM proposal

A supplied title-page screenshot identifies an independently authored
**HERESY-GEOM** specification by DeltaKingZero / Dr. John Robitaille. Its own visible
lineage note says it builds on the public `multimodalas/HERESY-SEC` determinism
contract without claiming ownership of that project.

No HERESY-GEOM source code or normative specification has been copied into this
repository. Its visible feature names are preserved only as attributed integration
notes in [HERESY_GEOM.md](HERESY_GEOM.md).
