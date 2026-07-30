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

The full academic specification was later supplied to the project. Its text and DOCX
are not redistributed here because redistribution permission was not provided.
HERESY-SEC v0.2.0 contains an independently written implementation profile derived
from the attributed architecture: action graphs, integer Forman curvature, exact
spectral fingerprints, authority holonomy, Shadow Guard state, evidence atoms,
impossible-configuration witnesses and geometric receipt chaining.

The architecture leaves byte-level and arithmetic choices open. Those choices are
clearly identified as HERESY-SEC's `heresy-geom.profile/v1`; no author certification,
endorsement, affiliation or ownership is claimed. See
[HERESY-GEOM status](HERESY_GEOM.md) and the
[implementation profile](HERESY_GEOM_PROFILE.md).
