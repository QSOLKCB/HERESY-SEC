# Changelog

All notable changes to HERESY-SEC are documented here.

## [Unreleased]

### Changed

- Established `QSOLKCB/HERESY-SEC` as the canonical project home.
- Preserved the earlier `multimodalas/HERESY-SEC` implementation as relocation
  provenance.

### Documentation

- Added an attributed HERESY-GEOM integration boundary without claiming that its
  unseen formal specification is implemented.
- Added deterministic acceptance requirements for future graph, curvature, holonomy,
  shadow-guard, atom-policy, impossible-configuration and KR-MPGM work.

### Fixed

- Converted run-directory and artifact-write operating-system failures into stable,
  machine-readable errors.
- Rejected symbolic links at every archive-tree level before recursion.
- Accepted lower-case RFC-style network schemes containing `+`, `.` or `-`.
- Updated the MPL 2.0 Exhibit A link to Mozilla's current HTTPS URL.
- Rejected undeclared symbolic links, special entries and directories during manifest
  verification.
- Accepted JSON whitespace before the top-level value while preserving exact captured
  bytes.
- Enforced canonical stored bytes for decisions and receipts during verification and
  replay.
- Bounded canonical JSON nesting and converted parser recursion into controlled
  failures.

## [0.1.0] - 2026-07-30

### Added

- Purpose-built `heresy_sec` standard-library Python package.
- Strict canonical JSON and domain-separated SHA-256 identities.
- Exact raw-byte capture for action and policy evidence.
- Deterministic `ALLOW`, `DENY` and `REVIEW` policy decisions.
- Hard authority, network, process, file, IPC and parameter-size boundaries.
- Open-weight, closed and model-free producer provenance without trust ranking.
- Hash-chained receipts, complete manifests and source-bundle identity.
- Verification, inspection, exact replay and deterministic archive commands.
- Runnable file, network, process and IPC examples.
- Unit tests, installed-artifact self-test, architecture audit and network audit.
- Deterministic 1,350,000-byte-budget zipapp build.
- GitHub Actions CI across Python 3.11, 3.12 and 3.13.
- Open Secure AI Alliance interoperability roadmap with explicit non-affiliation.

### Changed

- Replaced the inherited generic `qsolai` package with the security-specific
  `heresy_sec` runtime.
- Replaced aspirational README claims with an implementation-matched contract and
  explicit security boundaries.

### Removed

- Generic orchestration examples and high-stakes support profiles that do not belong
  in the focused HERESY-SEC v0.1.0 runtime.
- Prebuilt `dist/qsolai.pyz`; release artifacts are now rebuilt deterministically.
