---
name: dlv-feature
description: Deliver an end-to-end feature with a repository-agnostic, proof-carrying workflow. Use when implementation needs rigorous requirement coverage, risk-routed Review, generated delivery views, target-runtime evidence, and deterministic completion without repetitive review loops.
---

# DLV Feature

DLV minimizes delivery, Review, and rerun cost subject to: critical requirement
coverage = 100%, critical invariant Proof coverage = 100%, unresolved P0/P1
Findings = 0, unresolved P2 Findings without an Owner decision = 0, and false
Ready = 0. P3 Findings are advisory and never require a zero-Finding loop.

Schema v13 makes Product Lock, Claims, Review, and Proof quality contracts. Source Revision, deterministic
lint, risk routing, precise invalidation, Finding convergence, and recovery are
efficiency mechanisms. Do not trade the first set away to optimize the second.

## Truth and inputs

`delivery/{feature-id}/delivery-graph.json` is editable machine truth. PRD,
Architecture, Code Spec, diagrams, state, and Proof Contract are generated or
machine-maintained views; never repair them by hand.

The Graph owns stable `claims`; `claim_successions` is reserved and must remain empty. A Claim identity is derived from its risk lens,
invariant, sorted subjects, failure boundary, and criticality; review-unit partitioning is
never part of Claim or Finding identity. Use only the initial generic lenses:
`PROVENANCE_INTEGRITY`, `STATE_AND_ATOMICITY`,
`BOUNDARY_AND_CONCURRENCY`, and `RUNTIME_AUTHENTICITY`.

`source-revisions/SRC-*.json` is the immutable capture of issue title,
description, comments, typed attachments, Owner decisions, and R0 risk. Raw
product prototypes are Source attachments, never direct implementation contracts. Read
[artifact-contracts.md](references/artifact-contracts.md) before editing the
Graph. Consult a stage reference only when it applies: [PRD](references/prd-stage.md),
[Architecture](references/architecture-stage.md), [Code Spec](references/code-spec-stage.md),
[Prototype](references/prototype-stage.md), [implementation](references/implementation-stage.md),
or [runtime verification](references/verification-stage.md).

## Workflow

```bash
python3 <skill-dir>/scripts/semantic_review_preflight.py
python3 <skill-dir>/scripts/init_feature.py <feature-id> --root <project-root> --title "Feature title"
python3 <skill-dir>/scripts/scope_revision.py <feature-id> --root <project-root> capture --source /abs/issue-source.json --owner <owner>
python3 <skill-dir>/scripts/scope_revision.py <feature-id> --root <project-root> confirm --revision SRC-002 --owner <owner> --affected-node REQ-001
python3 <skill-dir>/scripts/delivery_graph.py compile <feature-id> --root <project-root>
python3 <skill-dir>/scripts/product_alignment.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/seal_product_lock.py <feature-id> --root <project-root> --alignment /abs/ALN-....json
```

Before running this plugin, the host or package manager must verify the release
digest/signature outside the plugin and load it from the verified snapshot.
`semantic_review_preflight.py` checks only the Codex executable and private
bootstrap-file environment. Its diagnostic plugin version/hashes are untrusted
observations, not a self-attested identity or permission to start Product Alignment.

Capture creates `SOURCE_DRIFT`; it does not mutate Graph or cancel a running
Review. Confirmation starts a new scope epoch. Name affected nodes for precise
invalidation; omission conservatively invalidates all attestations. Never carry
an old Source Revision into Ready.

When Product Alignment returns `NEEDS_DECISION`, persist only the precise Owner
answer and its reported decision subtype as a new confirmed Source epoch:

```bash
python3 <skill-dir>/scripts/scope_revision.py <feature-id> --root <project-root> resolve \
  --decision-id DEC-001 --question "..." --answer "..." \
  --reason platform_limitation --owner <owner> --affected-node AC-001
```

Then update the affected Graph nodes and `origins`, rebuild `prototype.html` and
its declaration when UI applies, compile to regenerate the PRD, rerun Product
Alignment, and seal the replacement Product Lock. Never request or record an
Owner decision for a safe clarification.

Risk is an additive vector, not a frontend/backend label:

```text
API_CONTRACT, PERSISTENCE, AUTHORIZATION, TENANCY, MONEY,
CONCURRENCY, IRREVERSIBLE_SIDE_EFFECT, CROSS_CLIENT, VISUAL_CONTRACT
```

DLV combines R0 (source), R1 (Graph), and R2 (declared Symbol code scan). It
can increase risk but never silently lowers it. `UI_LOCAL` applies only with no
API, persistence, authorization, money, business-state, cross-client, or
irreversible-side-effect impact. It still has Graph, semantic Review and Proof.

Compile after each Graph change. The compiler runs deterministic lint first,
derives stable typed components, retains exact fresh attestations, renders all
views, and refreshes global coherence.

Product work is source-first: normalize Source into product nodes, generate
`prd.md` and `prototype.html`, then compare both outputs to Source in an isolated
Codex process. Every Requirement, Behavior, Acceptance, and Exception declares
`origins`: `direct` points to source text/attachments; `derived` points to a
repository or platform constraint and records why. Safe clarification advances
automatically. `ambiguity`, `degradation`, `conflict`, `new_scope`, `unmapped`,
or `platform_limitation` produces `NEEDS_DECISION` with one precise Owner question.
Only a `SAFE` Product Alignment can seal `product-locks/PCL-*.json`.

The Product Lock binds Source revision/digest, product subgraph, generated PRD,
generated Delivery Prototype, alignment digest/verdict, source coverage, and
Owner decision references. It is content-addressed and immutable. Missing or
stale Product Lock blocks quality/architecture Review, Code, Proof, and finalization;
product drift invalidates every downstream attestation and Proof Contract.

After every compile, first honor `state.json.convergence`: `DIVERGING` or
`NEEDS_DECISION` stops automation for the precise Owner decision. Otherwise
route from `state.json.readiness`. The kernel
derives `authoring_stage`, typed `authoring_blockers`, `product_lock_state`, and
one `next_action`; the host must execute that action before considering Review:

```text
author_product_graph                 → Author LLM completes product truth
regenerate_prototype                 → generator rebuilds prototype bytes/binding
run_product_alignment                → isolated Product Alignment, then seal Lock
recover_product_lock                 → fail closed; investigate/restore trusted artifacts
author_architecture_graph            → Author LLM adds architecture nodes/edges/Claims
author_implementation_proof_graph    → Author LLM adds Code Spec and Proof graph truth
repair_blocking_findings             → implementer repairs P0/P1 Findings
run_quality_review                   → isolated Reviewer LLM may start
request_owner_decision               → ask one precise question and stop
seal_or_continue_delivery            → proceed to Proof Contract/code/runtime gates
```

The compiler and validator, not an LLM, derive this route from the same
convergence function. Product incompleteness precedes Product Alignment;
prototype drift precedes Lock; missing or content-stale Lock reruns Product
Alignment; an invalid/tampered Lock never gets overwritten automatically.
After a SAFE Lock, Architecture and implementation-proof Graph authoring must
be deterministically complete before Quality Review. Architecture and Code
Spec remain generated views, not approval stages.

Quality Review has a fail-closed preflight. While any deterministic
critical/major authoring blocker exists, it must not invoke Codex, mark
execution as reviewing, create transcripts or review records, or consume a
campaign. A `reviewing` execution lease blocks concurrent compilation until the
review records or recovers its checkpoint. Owner input remains limited to source ambiguity/conflict/degradation,
new scope, unmapped content, platform limitations, P2 outcomes, or exhausted
or diverging Review policy.

```bash
python3 <skill-dir>/scripts/delivery_graph.py compile <feature-id> --root <project-root>
python3 <skill-dir>/scripts/invalidate_downstream.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/quality_review.py <feature-id> --root <project-root> --run-id review-01
```

Review tracks the lexicographic vector `[critical_obligation_weight,
nonwaivable_major_obligation_weight, unproven_critical_claims,
major_obligation_weight, missing_proofs, stale_reviews, review_units]`.
OPEN and MERGE_CANDIDATE Findings weigh 2; FIXED_PENDING_REVIEW weighs 1,
so repair is measurable progress without pretending it is closed.
The kernel retains the latest three distinct vectors. If ready distance,
blocking Findings, or Review units increase across two consecutive transitions,
`DIVERGING` stops automatic expansion and Review. Review budget exhaustion
produces `NEEDS_DECISION`; it never waives a Claim.
Severity maps to delivery priority: `critical=P0`, `major=P1`, `moderate=P2`,
and `minor=P3`. P0/P1 must be fixed and independently verified. P2 must be
fixed, moved out of scope, or explicitly accepted by an Owner with a reason.
P3 may remain OPEN as non-blocking follow-up work. Do not optimize for zero
Findings after these gates pass.
Automatic Review is capped at three campaigns, even when Graph metadata asks
for more. If the third campaign is not Ready, stop at `NEEDS_DECISION`; do not
start a fourth automatic repair/review loop.
The Finding Ledger owns a convergence event record signed by an external RSA
private key. The confirmed Source Revision binds the repository-carried public
identity, so another machine or CI can verify history without signing authority.
Appending without the matching private key fails explicitly. Schema v13 does
not rotate authority in place; a future versioned rotation protocol must require
Owner approval and preserve the signed history. `state.json`
history/status are derived views and cannot reset divergence together.

Reviewers verify prior Findings before inspecting the delta and dependency path,
then apply global coherence. Every Finding binds `claim_id`, failure mode,
violated invariant, stable subjects, and risk axes. Exact semantic matches
reuse `FND-*` across unit repartitioning and append `observed_in_units`.
Partial overlap is `MERGE_CANDIDATE`; wording similarity never auto-merges.
Only the canonical Finding ID with matching canonical semantics can become
`VERIFIED`; a superseded alias can never verify its canonical target.

Finding lifecycle: `OPEN → FIXED_PENDING_REVIEW → VERIFIED`. Owner-only
outcomes are `OUT_OF_SCOPE`, `ACCEPTED_RISK`, and `SUPERSEDED`:

```bash
python3 <skill-dir>/scripts/finding_ledger.py <feature-id> --root <project-root> \
  --finding FND-... --status FIXED_PENDING_REVIEW --owner <implementer> --reason "Implemented and ready for independent re-review"
python3 <skill-dir>/scripts/finding_ledger.py <feature-id> --root <project-root> \
  --finding FND-... --status OUT_OF_SCOPE --owner <owner> --reason "..."
python3 <skill-dir>/scripts/finding_ledger.py <feature-id> --root <project-root> \
  --finding FND-candidate --status SUPERSEDED --superseded-by FND-canonical \
  --owner <owner> --reason "Confirmed semantic overlap"
```

TENANCY, AUTHORIZATION, MONEY, and irreversible-side-effect risks are not
waivable. `STABLE_BLOCKED`, `DIVERGING`, or `NEEDS_DECISION` requires Owner action; do not
automatically rewrite the Graph until a decision changes the facts.

Delivery Prototype is `generated` or `not_applicable`. There is no
`reference`/`contractual` escape hatch. A visible UI uses generated
`prototype.html`, bound to the current Source Revision and then sealed by the
Product Lock. Visual Proof compares implementation only with that locked
Delivery Prototype, never with a raw product prototype attachment.
Architecture and Code Spec remain generated Graph views, never serial approval
stages.

Configure `.dlv/repository-adapter.json` for repository-specific parameter-array
commands. The adapter exposes discovery, lint, tests, typecheck, build,
integration, runtime, database, and browser capabilities with bounded
time/output. It cannot decide PASS, reduce risk, or waive Claims.
On macOS each executable capability also declares a preinstalled
`sandbox_image`; execution pins its immutable OCI image ID and uses a
network-disabled, resource-limited disposable container.
Its `frontend_roots` and adapter SHA bind a `repository_adapter` attachment in
the confirmed Source Revision. The kernel freezes Git base/merge-base OIDs,
changed paths, adapter SHA, and Code fingerprint before execution, then
rechecks them after every capability.
Its `changes` capability emits exact adapter schema-v12 JSON with sorted `paths`,
`surfaces`, and `risk_axes`; invalid, empty, or elevated output routes to the
standard path.

Only after the quality core is valid, a pure frontend change may use:

```bash
python3 <skill-dir>/scripts/frontend_fast_path.py <feature-id> --root <project-root> --run-id fast-01
```

The fast path is provenance → lint/change discovery → targeted tests →
typecheck → build → one composite Review → fresh Proof. API, persistence,
auth, tenancy, money, concurrency, cross-client, or side-effect risk routes to
the standard path. Fast scheduling never changes Ready or Proof strength.

When Readiness is current and ready, seal, reconcile Code risk, verify the
target runtime, and finalize:

```bash
python3 <skill-dir>/scripts/seal_proof_contract.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/reconcile_code.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/delivery_graph.py mark-code-complete <feature-id> --root <project-root>
python3 <skill-dir>/scripts/verification_run.py start <feature-id> --root <project-root> --run-id run-01 --environment ENV-001=/abs/env.json
python3 <skill-dir>/scripts/verification_run.py record <feature-id> --root <project-root> --run-id run-01 --result /abs/result.json
python3 <skill-dir>/scripts/finalize_delivery.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/validate_feature.py <feature-id> --root <project-root> --final
```

High-strength runtime/invariant/visual Proof requires committed source with a
HEAD `DLV-Feature` trailer and binds the real Git commit OID, Code fingerprint,
build, deployment, runtime target, repository-adapter SHA, fixture SHA, and a kernel-issued
challenge nonce. The target signs the challenge, identities, and measurement
digest with a pinned RS256 public key; the kernel verifies it and never gives
the runner the expected target identity. Boolean-only observations are
rejected. Runtime action, readback, and trace must share target identity and
nonce. Drift invalidates the evidence; visual metrics are always recomputed
from runner-bound captures.

Repository-controlled adapter, preflight, Proof runner, and semantic-review
processes run under an OS file sandbox that denies convergence signing
credentials. If macOS `sandbox-exec` or Linux `bwrap` is unavailable, fail
closed instead of executing repository code beside the signer.
macOS high-strength Proof commands deny child-process creation. Repository
adapter commands that need a process tree run in a disposable repository copy,
with the real workspace write-denied; semantic review runs only against its
disposable immutable snapshot. Linux uses PID-namespace containment directly.

Critical state/concurrency Claims require invariant/runtime Proof, explicit
Assertion `subject_ids`, one unique authoritative measurement per business
subject, and state or side-effect readback. Claim semantic changes create a new
ID and a new obligation. Never auto-route historic Findings through a claimed
natural-language "strengthening". Resolve the predecessor explicitly only after
independent Review. Unit repartitioning needs no migration because unchanged
Claim IDs and semantic Finding IDs remain stable.

Use formal commit trailer `DLV-Feature: <feature-id>`. A formal commit while
Code is pending becomes `needs_reconcile`, never a false pending state. Review
jobs retain `needs_resume` checkpoints and use `needs_decision` for Owner work.

Import v11 with `upgrade_v11_to_v12.py`. It preserves Source Revision and Graph
semantics, archives mutable review/finding/proof records, and promotes no old
seal, PASS, Ready, or Product Lock claim. Import v12 with
`upgrade_v12_to_v13.py`; it preserves the original bytes under `archive-v12`
and requires fresh Product Alignment. Compatibility importers for v9/v10 emit
the same untrusted v13 state. Finalization emits `delivery-manifest.json` with a
deterministic tree digest for Multica artifact retention; remote upload receipts
remain outside the DLV schema.
Read [workflow.md](references/workflow.md) for operating detail. Claim
completion only when final validation reports zero errors.
