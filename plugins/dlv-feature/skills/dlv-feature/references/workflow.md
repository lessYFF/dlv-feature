# Schema v13 workflow

```text
capture source → confirm epoch → declare Claims/Graph → compile
→ review stale risk components → converge Findings
→ seal → implement/reconcile → authentic target Proof → finalize
```

Quality contracts never change by route. Efficiency may reuse fresh component
attestations, run cheapest checks first, or select the frontend fast path; it
cannot weaken Claim meaning, Finding closure, Proof strength, or Ready.

## Review control

Review uses four generic risk lenses plus global coherence. Findings bind
Claims, not units. Exact semantic duplicates merge across Graph repartition;
partial overlap waits as `MERGE_CANDIDATE` for a decision.

After each effective change append the convergence vector to the Finding
Ledger's externally signed event stream. The confirmed Source Revision binds
its repository-carried RSA public identity; the private key remains external.
Cross-machine verification requires no private key, while append or rebaseline
without the matching authority must fail. Schema v13 rejects authority rotation;
support requires a future Owner-approved versioned migration that preserves the
existing signed chain. Derive the
three-point state history from the stream. Stop new units, Graph expansion, and automatic Review when
ready distance, blocking Findings, or Review units rise across two consecutive
transitions (`DIVERGING`), or when a source/Product Lock/budget decision is needed
(`NEEDS_DECISION`). `STABLE_BLOCKED` means no progress and requires repair or an
Owner decision. Budget exhaustion never synthesizes a waiver or PASS.
Automatic Review has a hard maximum of three campaigns. Configuration may use
one or two but never more than three. After the third non-Ready campaign, stop
automatic iteration and ask the Owner to choose; do not chase a zero-Finding
result.

Risk acceptance is priority-based: critical/P0 and major/P1 Findings must be
fixed and independently verified. Moderate/P2 Findings require an explicit
Owner outcome (`FIXED_PENDING_REVIEW`, `OUT_OF_SCOPE`, or `ACCEPTED_RISK` with
a reason). Minor/P3 Findings are advisory and may remain OPEN. Delivery
continues when no known P0/P1 or undecided P2 remains, even if P3 follow-up
Findings exist.

## Fast path

For a pure local frontend change, configure the repository adapter and set
`metadata.delivery_mode=frontend_fast_path`. The order is provenance, lint and
change discovery, targeted tests, typecheck, build, one composite Review, then
fresh Proof. Any elevated API/data/auth/tenant/money/concurrency/cross-client/
side-effect risk routes to standard delivery. A Finding repair always gets an
independent re-review.
The changes adapter must return structured paths/surfaces/risk axes; output that
is malformed, empty, or crosses the frontend boundary routes to standard.
An atomic per-feature reservation admits only one fast-path run. Long-running
checks execute outside the feature lock, and an interrupted reservation fails
closed until it is reconciled.

## Recovery

Feature locks serialize Graph/state/ledger writes. Review runs in independent
read-only processes. Verification uses a pending-execution WAL and append-only
hash chain. Ambiguous side effects fail closed. Source, adapter, fixture,
environment, target, or code drift invalidates dependent claims rather than
relabeling stale evidence.
