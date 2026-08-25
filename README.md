# DLV Feature

Current plugin version: **0.6.0**, Delivery Graph schema v10.

DLV Feature is a proof-carrying Codex workflow with one editable Delivery Graph, deterministic component-scoped review reuse, a compact global system-coherence review, generated delivery views and contracts, target-runtime evidence, and deterministic finalization.

Architecture and Code Spec are generated views, not serial approval stages. A local edit invalidates only its dependency component. Owner, Boundary, StateTransition, critical/major Risk, shared Fact, or shared Environment changes also invalidate the Global Skeleton attestation.

## Install

```bash
codex plugin marketplace add lessYFF/dlv-feature
codex plugin add dlv-feature@dlv-feature-marketplace
```

## Core flow

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/init_feature.py feature-id --root /path/to/project --title "Feature title"
python3 plugins/dlv-feature/skills/dlv-feature/scripts/delivery_graph.py compile feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/quality_review.py feature-id --root /path/to/project --run-id review-01
python3 plugins/dlv-feature/skills/dlv-feature/scripts/seal_proof_contract.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/delivery_graph.py mark-code-complete feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/verification_run.py start feature-id --root /path/to/project --run-id run-01 --environment ENV-001=/path/to/env.json
python3 plugins/dlv-feature/skills/dlv-feature/scripts/verification_run.py record feature-id --root /path/to/project --run-id run-01 --result /path/to/result.json
python3 plugins/dlv-feature/skills/dlv-feature/scripts/finalize_delivery.py feature-id --root /path/to/project
```

## Import a schema-v9 delivery

Schema v10 does not create or execute legacy deliveries. It keeps one conservative import boundary:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v9_to_v10.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v9_to_v10.py feature-id --root /path/to/project --apply
```

The importer archives source bytes exactly, verifies every digest before legacy cleanup, and invalidates all prior completion claims.

## Test

```bash
python3 -m unittest plugins/dlv-feature/skills/dlv-feature/scripts/test_delivery_graph.py
python3 /path/to/skill-creator/scripts/quick_validate.py plugins/dlv-feature/skills/dlv-feature
```
