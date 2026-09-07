# Changelog

All notable changes to DLV Feature are documented here.

## [0.12.0] - 2026-09-07

### Changed

- Keep Graph, Product Lock and authentic Proof while separating source coverage from business-risk severity.
- Require old-client/new-server workflow evidence for API or mandatory-step changes; extend cross-client risk discovery.
- Reserve prospective review units before model calls and count failed/interrupted/recovery attempts against the existing budget.
- Preserve valid peer attestations after unit failure and resume only missing or stale units without granting partial Ready.
- Constrain semantic-review output to the current unit's Claim and Subject IDs.

### Validation

- Add WMD-238-style partial-failure/recovery, preflight budget, retry-budget and local-schema regressions.
- Add a WMD-221-style old-client risk-discovery regression; this is not a replay of the production mini-program.

## [0.11.0] - 2026-09-03

### Added

- Record a minimal, non-blocking quality and efficiency assessment for every terminal DLV execution.
- Append later user, Review, or production defect feedback without rewriting the original assessment.

### Changed

- Evaluate first-pass completeness, final functional/visual/edge quality, critical coverage, and false Ready before comparing delivery efficiency.
- Preserve all observed deviations while selecting one primary target for the next skill improvement.

## [0.10.0] - 2026-09-03

### Added

- Capture verified Source attachment content and derive stable clause-level coverage anchors automatically.
- Reconcile planned Graph Subjects with the complete baseline-to-worktree implementation delta before completion.
- Derive a minimal risk frontier and kernel-executed, signed critical experiment evidence.
- Distinguish `REVIEWABLE` from final `DELIVERY_READY` completion.
- Add a three-domain first-pass quality benchmark and regression suite.
- Constrain attachment reads to the project root, cover binary Sources explicitly, and preserve a fail-closed locator-only schema-v13 recapture path.
