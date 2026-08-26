# DLV Feature

Current plugin version: **0.7.0**, Delivery Graph schema v11.

DLV Feature is a proof-carrying Codex workflow with one editable Delivery Graph, immutable Scope Revisions, risk-routed component reviews, a stable Finding Ledger, convergence/recovery control, generated delivery views and contracts, target-runtime evidence, and deterministic finalization.

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

## Import legacy deliveries

Schema v11 does not promote legacy completion claims. Import schema v10 directly:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v10_to_v11.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v10_to_v11.py feature-id --root /path/to/project --apply
```

For schema v9, use `upgrade_v9_to_v10.py`; it emits an untrusted v11 candidate. Import archives mutable source bytes and invalidates all prior completion claims.

## Test

```bash
python3 -m unittest plugins/dlv-feature/skills/dlv-feature/scripts/test_delivery_graph.py
python3 /path/to/skill-creator/scripts/quick_validate.py plugins/dlv-feature/skills/dlv-feature
```
