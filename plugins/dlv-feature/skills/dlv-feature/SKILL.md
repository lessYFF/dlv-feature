---
name: dlv-feature
description: Deliver an end-to-end feature with a repository-agnostic, proof-carrying workflow. Use when implementation needs rigorous requirement coverage, risk-routed Review, generated delivery views, target-runtime evidence, and deterministic completion without repetitive review loops.
---

# DLV Feature

DLV minimizes delivery, Review, and rerun cost subject to: critical requirement
coverage = 100%, critical invariant Proof coverage = 100%, unresolved Critical
= 0, non-waivable Major = 0, and false Ready = 0.

Graph, Review, and Proof are quality mechanisms. Scope Revision, deterministic
lint, risk routing, precise invalidation, Finding convergence, and recovery are
efficiency mechanisms. Do not trade the first set away to optimize the second.

## Truth and inputs

`delivery/{feature-id}/delivery-graph.json` is editable machine truth. PRD,
Architecture, Code Spec, diagrams, state, and Proof Contract are generated or
machine-maintained views; never repair them by hand.

`source-revisions/SRC-*.json` is the immutable capture of issue title,
description, comments, attachments, and R0 risk. Read
[artifact-contracts.md](references/artifact-contracts.md) before editing the
Graph. Consult a stage reference only when it applies: [PRD](references/prd-stage.md),
[Architecture](references/architecture-stage.md), [Code Spec](references/code-spec-stage.md),
[Prototype](references/prototype-stage.md), [implementation](references/implementation-stage.md),
or [runtime verification](references/verification-stage.md).

## Workflow

```bash
python3 <skill-dir>/scripts/init_feature.py <feature-id> --root <project-root> --title "Feature title"
python3 <skill-dir>/scripts/scope_revision.py <feature-id> --root <project-root> capture --source /abs/issue-source.json --owner <owner>
python3 <skill-dir>/scripts/scope_revision.py <feature-id> --root <project-root> confirm --revision SRC-002 --owner <owner> --affected-node REQ-001
python3 <skill-dir>/scripts/delivery_graph.py compile <feature-id> --root <project-root>
```

Capture creates `SOURCE_DRIFT`; it does not mutate Graph or cancel a running
Review. Confirmation starts a new scope epoch. Name affected nodes for precise
invalidation; omission conservatively invalidates all attestations. Never carry
an old Source Revision into Ready.

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

```bash
python3 <skill-dir>/scripts/delivery_graph.py compile <feature-id> --root <project-root>
python3 <skill-dir>/scripts/invalidate_downstream.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/quality_review.py <feature-id> --root <project-root> --run-id review-01
```

Reviewers verify prior Findings before inspecting the delta and dependency path,
then apply global coherence. A new Major requires evidence, risk path, root
cause, and why it was not previously visible. Duplicate root causes reuse a
stable `FND-*` ID; omitted prior Findings remain open.

Finding lifecycle: `OPEN → FIXED_PENDING_REVIEW → VERIFIED`. Owner-only
outcomes are `OUT_OF_SCOPE`, `ACCEPTED_RISK`, and `SUPERSEDED`:

```bash
python3 <skill-dir>/scripts/finding_ledger.py <feature-id> --root <project-root> \
  --finding FND-... --status FIXED_PENDING_REVIEW --owner <implementer> --reason "Implemented and ready for independent re-review"
python3 <skill-dir>/scripts/finding_ledger.py <feature-id> --root <project-root> \
  --finding FND-... --status OUT_OF_SCOPE --owner <owner> --reason "..."
```

TENANCY, AUTHORIZATION, MONEY, and irreversible-side-effect risks are not
waivable. `STABLE_BLOCKED` / `NEEDS_DECISION` requires Owner action; do not
automatically rewrite the Graph until a decision changes the facts.

Prototype is `reference`, `contractual`, or `not_applicable` with a reason.
Contractual Prototype requires visual Proof; reference is reviewed as intent.
Architecture and Code Spec remain generated Graph views, never serial approval
stages.

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

Use formal commit trailer `DLV-Feature: <feature-id>`. A formal commit while
Code is pending becomes `needs_reconcile`, never a false pending state. Review
jobs retain `needs_resume` checkpoints and use `needs_decision` for Owner work.

Import v10 conservatively with `upgrade_v10_to_v11.py`; it archives mutable
v10 artifacts and promotes no old Review, seal, Code, run, or PASS claim.
`upgrade_v9_to_v10.py` now emits the equivalent untrusted v11 candidate.
Read [workflow.md](references/workflow.md) for operating detail. Claim
completion only when final validation reports zero errors.
