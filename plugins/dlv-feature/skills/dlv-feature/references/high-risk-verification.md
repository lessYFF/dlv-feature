# High-risk verification obligations

Use these obligations when database evolution, supported-client behavior,
account authorization, or money/concurrency changes apply. Reuse existing
Fact, Boundary, Risk, Claim, Test, Proof and Assertion nodes. Do not introduce
a second contract file, a new approval stage, or one Claim per checklist item.
Independent Review must assess completeness against actual implementation and
source facts; the local accident benchmark cannot establish that completeness.

## Executable Graph contract

Each Risk whose axes include PERSISTENCE, API_CONTRACT/CROSS_CLIENT,
AUTHORIZATION/TENANCY, MONEY or CONCURRENCY requires
`attributes.verification={symbols, domains}`. Source and observed code risks
also require a corresponding modeled Risk; omitting it cannot bypass the gate.
`symbols` lists actual source-file Symbol IDs, including every Symbol of the
Risk's mitigating Changes. It may include relevant test/consumer source files.

`domains` contains exactly the applicable domain names below. Each domain is
`{context, checks}`. Each check maps the listed role to an existing Assertion ID.
The Assertion must measure `/observation/...`, use `eq/lte/gte` with a concrete
non-boolean expected value, and bind business subjects of a critical Claim
containing this Risk. Its Proof must be runtime/invariant and bound to that Claim.
Roles within one domain cannot reuse the same measurement. A single Proof may
cover several roles/domains; no new node is needed just to increase check count.

| Domain | Required context | Required check roles |
|---|---|---|
| database | engine, engine_version, change_kind=data/schema/destructive_schema | data_preservation |
| database, schema or destructive_schema | from_schema, to_schema, consumers (nonempty list), rollback_boundary | also legacy_io, migration_recovery |
| database, destructive_schema | recovery_method, destructive_execution_conditions | also consumer_retirement, recovery_readback |
| compatibility | supported_clients (nonempty list), historical_state, rollout_order, reverse_combination=required/unreachable | legacy_workflow, legacy_readback; reverse_workflow if required; otherwise concrete reverse_reason |
| authorization | principal_scope, resource_scope, revocation_max_seconds (nonnegative integer) | allowed_access, denied_access, denied_side_effects, revoked_session, revocation_window; also tenant_isolation for TENANCY |
| money | currency, unit, business_key | amount_invariant, side_effect_count |
| concurrency | schedule, failure_point | interleaving, invariant_readback |

`denied_side_effects` must assert integer `eq 0`. `revocation_window` must use
`lte` with exactly the declared `revocation_max_seconds`; measure the latest
observed permitted access after revocation (zero when all probes are denied),
using a schedule that actually exercises the claimed window. This bounds the
tested schedule, not every possible interleaving. Role labels and nonempty
context are necessary structure, not proof of semantic adequacy. The Reviewer
must challenge thresholds, actual scenario coverage, missing affected consumers
and whether the measurement establishes the claimed invariant.

For example, a compatibility Risk can reuse existing assertions:

```json
{
  "symbols": ["SYM-001"],
  "domains": {
    "compatibility": {
      "context": {
        "supported_clients": ["mini-program-v1"],
        "historical_state": "Order created before server rollout, awaiting payment",
        "rollout_order": "New server while v1 remains supported",
        "reverse_combination": "unreachable",
        "reverse_reason": "This release does not replace the client"
      },
      "checks": {
        "legacy_workflow": "ASRT-101",
        "legacy_readback": "ASRT-102"
      }
    }
  }
}
```

Prepare implementation files and the existing Environment fixture before
Quality Review. The kernel embeds actual source before/after the frozen Git
baseline and verifies the fixture's existing SHA. Inputs must be regular,
UTF-8 files, at most 128 KiB each and 512 KiB total per unit; unsupported/missing
inputs fail closed before spending a Review campaign. Use focused source files
and a reviewable fixture manifest for large client artifacts, not truncated
code or an unbound summary. The runner must still exercise the actual bound
artifact on its target. Obvious destructive table DDL cannot declare `data` or
non-destructive `schema` context to omit recovery/retirement checks.

Existing local files referenced directly by runner argv are included as well.
Use `Proof.attributes.review_paths` for relevant imported helpers and indirect
runner dependencies that argv does not expose. These paths need not be changed
Symbols; their exact bytes bind Review and invalidate it on change. External
executables and dynamically imported dependencies are not inferred as reviewed.

Isolated execution records bind `implementation_sha256`. Before publishing or
reusing a Review, sealing Proof, completing Code and finalizing delivery, live
source/fixture bytes must match it. Changing one component retains unaffected
attestations. Old high-risk Graphs lacking these obligations require authoring
and fresh Review; do not hand-edit old attestations or invent evidence.

## Database evolution and old consumers

Bind the actual migration files as Symbols and the current/target database
engine and version in the relevant Environment. `schema_sql` describes the
intended structure; it does not prove the migration path is safe.

For destructive or narrowing changes, identify the affected consumers,
including old server instances, jobs, scripts and reports. Verify the actual
migration against representative historical values (null, duplicate, boundary,
precision and constraint cases). Assert value/meaning preservation as well as
row counts. Execute old and new supported read/write paths against the migrated
database. Verify interrupted backfill, retry and concurrent writes when these
are independent failure boundaries.

Default to expand, migrate, switch and later contract when consumers cannot
switch atomically. Do not require dual writes when a simpler compatible
transition suffices. If dual writes are used, verify their consistency and exit.
Lock duration, table rewrite, storage and replication claims need the actual
database engine and representative scale; SQLite fixtures cannot prove them.

Dropping a column/table is a separate execution from deploying compatible code.
Record consumer retirement evidence, allowed server/schema combinations,
rollback cutoff and the recovery method in the relevant Graph statements and
dependencies. A backup alone is not a recovery proof: exercise recovery and
measure time and treatment of intervening writes. Before the destructive action,
recheck live prerequisites under the authorization for that action.
`DELIVERY_READY` neither authorizes deletion nor proves future prerequisites.

## Supported clients

Identify the supported versions/behaviors from source and repository evidence;
do not assume N-1. Freeze the old request fixture or client artifact and bind its
digest through the existing Environment fixture. Replay the old action sequence
against the new server with historical/in-flight state, and assert completion
plus authoritative readback, not only an intermediate HTTP response.

Cover missing new fields, old enum handling, old step order, retries and cached
state where affected. Test reverse server/client combinations only when release
or rollback can produce them. Group versions only with evidence of equivalent
behavior. Protocol replay is not evidence for client rendering, parsing or
mini-program lifecycle behavior; those need the applicable client runtime.
Never fabricate missing user consent to keep an old flow passing.

## Accounts, authorization and money

State the actual revocation policy, including any allowed propagation window.
Probe sessions issued before account disablement, role change or tenant exit.
Cover cross-user/tenant access, sensitive field exposure and affected alternate
entry points. For denied writes, assert both rejection and absence of database,
queue and external side effects; a 403 alone is insufficient.

For money and concurrency, define business-key uniqueness and amount invariants.
Force the relevant interleaving and failure point: duplicate callback, lost
response after commit, competing refund, or authorization change before write.
Read authoritative state and external effects. A controlled interleaving checks
one schedule; it is not a load test or a universal exactly-once guarantee.

## Local regression baseline and limits

Run `python3 <skill-dir>/scripts/high_risk_baseline.py` for JSON results, or
`python3 -m unittest <skill-dir>/scripts/test_high_risk_baseline.py` for regressions.
Five fixed accidents each have correct/defective implementations and independent
expected values in `high-risk-baseline.json`. Real local operations feed the
existing delivery oracle. Weak checks deliberately accept defective controls,
demonstrating why business readback is required.

The standalone controls assess fixture execution and assertion evaluation.
`test_high_risk_contracts.py` additionally checks required roles, mutation
rejection and source/fixture/runner binding. `test_high_risk_delivery.py` drives
all five pairs through the actual sealing, signature-verification and finalization
gates in temporary projects. Its model and target transport are test doubles;
local SQL and target signatures use real execution and test keys respectively.
These suites do not measure semantic Reviewer recall, production migration
behavior or real client compatibility. Keep these outcomes separate when
comparing versions. Missing domain evidence must remain a delivery limitation;
a green benchmark does not supply it.
