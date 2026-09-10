# High-risk baseline coverage

Scope: local executable controls and deterministic kernel regressions. No
production database, real client, deployment, or external message is involved.

## Reproduced discovery gaps and repairs

- Bare DROP/ALTER/TRUNCATE TABLE statements were not detected as persistence
  risk without other keywords. SQL table DDL now raises PERSISTENCE; destructive
  table operations and potentially narrowing ALTER operations also raise
  IRREVERSIBLE_SIDE_EFFECT. A plain ADD COLUMN is not automatically destructive.
- Removed files and deleted authorization/compatibility logic disappeared from
  current-file-only R2 scans. The scan now includes added/removed lines from the
  frozen implementation baseline, and directory Subjects include child files.
- Code completion and frontend routing now preserve previously observed risk;
  removing a signal does not waive the obligation to reconcile it.
- Explicit unavailable baseline commits fail closed. Literal Git pathspecs and
  non-following of symlinked parents keep discovery scoped to declared Subjects.

Existing camelCase/snake_case client-version detection passed its new controls;
it did not require a speculative regex change.

## Executable accident controls

| Accident | Correct control | Injected defect | Required observation |
|---|---|---|---|
| Old service after column migration | Add/backfill while retaining old column | Prematurely drop old column | Old query succeeds and both values match |
| Money precision loss | Preserve exact minor units | Truncate sub-unit amounts | Exact positive/negative/small values and row count |
| Old-client payment | Historical payment endpoint still completes intent | Require a new confirmation field | Payment result, paid state and charged amount |
| Disabled account with old session | Check current account state | Trust cached enabled flag | Denial and zero mutations |
| Duplicate payment callback | Unique business-key constraint | Both stale absence checks insert | One posting and one charged amount |

All controls execute local SQLite operations or a fixed request handler. The
callback control forces read/read/write/write, not a production concurrency or
capacity workload. Expected values are fixed separately from observations.
Each defect passes its deliberately weak check and fails its business oracle;
each correct implementation passes the full oracle set.

## Enforced delivery obligations

The existing Risk/Claim/Proof graph now enforces domain context and measured
check roles for database evolution, compatibility, authorization, money and
concurrency. Source and observed risk cannot be waived by omitting a Risk.
Required TENANCY cannot be substituted by an AUTHORIZATION-only declaration;
this gap was found in independent forward-testing and fixed with a regression.
Account denial requires zero side effects, and the measured revocation window
must use the declared maximum rather than an unrelated permissive threshold.

Independent Review receives bounded before/after source, verified fixture bytes,
local runner files and explicitly declared runner dependencies. Missing or
oversized inputs stop before a model call or campaign reservation. Implementation
digests are checked before publishing and reusing reviews, sealing Proof,
completing Code and validating delivery. Unaffected reviews remain reusable.
Obvious destructive table DDL cannot omit recovery and consumer-retirement
obligations by declaring an ordinary data/schema change.

`test_high_risk_delivery.py` runs each of the five correct/defective pairs
through Review, Proof sealing, signed target observations, assertion evaluation
and finalization. Correct controls reach DELIVERY_READY; defective controls
fail their business assertions and cannot finalize. SQL operations, RSA
signature verification and kernel gates execute for real. Model responses and
target transport are test doubles; the test key is not a production identity.
Additional controls check preflight budget preservation, scoped invalidation
and source changes immediately before Review publication.

## Remaining gaps (not claimed solved)

- Risk discovery remains heuristic and restricted to declared Subjects; missed
  consumers and unrecognized SQL/ORM semantics require independent inspection.
  Mapping all changed paths remains the existing reconciliation gate.
- Domain structure and bindings are enforced, but semantic sufficiency is not
  decidable from role names. A Reviewer accepting an insufficient scenario or
  oracle can still miss a defect. This benchmark does not measure that rate.
- Actual production-engine DDL locking, narrowing behavior, data scale,
  backfill concurrency and recovery need repository-specific executable Proof.
- Fixed legacy requests do not establish real mini-program/client compatibility.
- Full account lifecycle, tenant isolation, external payment side effects and
  process-crash schedules need additional real fixtures.
- External executables and undeclared dynamic dependencies are not automatically
  included in source Review. Declare relevant indirect sources in review_paths.
- The standalone baseline does not grant DELIVERY_READY. The integration suite
  exercises that gate only in temporary test projects. Neither authorizes a
  production destructive execution or proves its future prerequisites.

Run `python3 <skill-dir>/scripts/high_risk_baseline.py` for machine-readable
measurements and `python3 -m unittest <skill-dir>/scripts/test_high_risk_baseline.py`
for accident and risk-discovery regressions. Run `test_high_risk_contracts.py`
for domain mutation/source evidence tests and `test_high_risk_delivery.py` for
the signed local integration controls. Existing Delivery Graph regressions
continue to cover the surrounding gates.

## Verification on 2026-09-10

- Delivery Graph suite: 235 tests, OK, two Linux-only tests skipped on macOS
  (133 seconds). The initial full run exposed four integration regressions:
  invalid Source diagnostics, authoring/preflight ordering, stale fixture error
  expectations and a test changing implementation after Review. All were fixed,
  passed targeted reruns and passed the final complete suite.
- Domain contract/source evidence suite: 10 tests, OK.
- Accident/risk-discovery suite: 15 tests, OK.
- Signed local delivery suite: 5 tests, OK (40 seconds), including all 10
  correct/defective finalization paths and preflight/publication-race controls.
- Quality core and execution assessment: 23 tests, OK.
- Total: 288 tests, 286 passed and two platform skips. Repeated mock-model
  fixtures no longer copy/code-sign the host Codex binary; dedicated isolation
  and executable-preflight tests remain. This is a test-harness optimization,
  not a measurement of production delivery or real-model latency.
- Baseline JSON command: all five correct controls accepted, all five defective
  controls rejected by the full oracles; weak checks accepted all five defects.
- Skill structural validation passed; `git diff --check` is clean.
- No external database/client validation was run.
