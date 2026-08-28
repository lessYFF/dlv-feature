# DLV Feature

Current plugin version: **0.8.0**, Delivery Graph schema v12.

DLV Feature is a proof-carrying Codex workflow with one editable Delivery Graph, immutable Scope Revisions, source-bound Prototypes, stable Claims and semantic Findings, budgeted convergence control, thin repository adapters, target-runtime authenticity, and deterministic finalization.

Review is risk-gated rather than zero-Finding-gated: critical/P0 and major/P1
Findings block delivery, moderate/P2 requires an explicit Owner decision, and
minor/P3 is advisory. Automatic Review is capped at three campaigns; a third
non-Ready result moves to `NEEDS_DECISION` instead of starting another loop.

Architecture and Code Spec are generated views, not serial approval stages. A local edit invalidates only its dependency component. Owner, Boundary, StateTransition, critical/major Risk, shared Fact, or shared Environment changes also invalidate the Global Skeleton attestation.

## Install

```bash
codex plugin marketplace add lessYFF/dlv-feature
codex plugin add dlv-feature@dlv-feature-marketplace
```

## Core flow

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/init_feature.py feature-id --root /path/to/project --title "Feature title"
python3 plugins/dlv-feature/skills/dlv-feature/scripts/scope_revision.py feature-id --root /path/to/project capture --source /path/to/issue-source.json --owner owner
python3 plugins/dlv-feature/skills/dlv-feature/scripts/scope_revision.py feature-id --root /path/to/project confirm --revision SRC-002 --owner owner --affected-node REQ-001
python3 plugins/dlv-feature/skills/dlv-feature/scripts/delivery_graph.py compile feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/quality_review.py feature-id --root /path/to/project --run-id review-01
python3 plugins/dlv-feature/skills/dlv-feature/scripts/seal_proof_contract.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/reconcile_code.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/delivery_graph.py mark-code-complete feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/verification_run.py start feature-id --root /path/to/project --run-id run-01 --environment ENV-001=/path/to/env.json
python3 plugins/dlv-feature/skills/dlv-feature/scripts/verification_run.py record feature-id --root /path/to/project --run-id run-01 --result /path/to/result.json
python3 plugins/dlv-feature/skills/dlv-feature/scripts/finalize_delivery.py feature-id --root /path/to/project
```

Pure frontend work may use the quality-preserving fast path after configuring
`.dlv/repository-adapter.json`. On macOS each capability also needs a locally
preinstalled `sandbox_image`; the adapter resolves it to an immutable image ID
and never pulls during delivery:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/frontend_fast_path.py feature-id --root /path/to/project --run-id fast-01
```

## Import legacy deliveries

Schema v12 does not promote legacy completion claims. Import schema v11 directly:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v11_to_v12.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v11_to_v12.py feature-id --root /path/to/project --apply
```

Compatibility importers for schema v9/v10 emit an untrusted v12 candidate. Import archives mutable records and invalidates all prior completion claims.

## Test

```bash
python3 -m unittest plugins/dlv-feature/skills/dlv-feature/scripts/test_delivery_graph.py
python3 /path/to/skill-creator/scripts/quick_validate.py plugins/dlv-feature/skills/dlv-feature
```
