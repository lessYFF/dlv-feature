# Schema v10 workflow

## Continuous truth and readiness

Only `delivery-graph.json` is edited. `prototype.html` is additionally editable when Prototype is completed. Compilation validates the graph, renders PRD/Architecture/Code Spec as disposable views, derives the Proof Contract, computes deterministic review components, preserves exact fresh attestations, and updates Delivery Readiness.

```text
edit graph → compile → review stale units → readiness
→ seal → Code → runtime proof → finalize
```

There is no Architecture-to-Code-Spec approval handoff. Those views help humans inspect different slices of the same graph.

## Deterministic local components

Each lens is partitioned from its typed roots and graph edges. The caller cannot provide a component boundary. A unit binds `(lens, component_id, component_hash)` and contains its exact roots plus required upstream dependencies. A changed node invalidates only units whose recomputed hash changes.

For `derives_from/changes/depends_on/tests/proves/runs_in/mitigates`, source depends on target. For `owns/guards`, the protected target depends on the provider. Explicit semantic changes that graph bytes cannot reveal use `--changed-node`.

## Global Skeleton

Local correctness is insufficient for a composed system. A compact global unit covers all Owner, Boundary, StateTransition, and critical/major Risk structure plus Fact/Environment context shared by multiple local units. It changes only when that system skeleton changes. A local Symbol or isolated proof edit does not trigger it.

The reviewer receives an immutable unit snapshot. Normal reviews run in independent read-only Codex processes outside the repository so repository instructions cannot steer them. A deterministic critical/major issue, failed semantic check, semantic `BLOCKED`, or open critical/major finding blocks that unit.

Delivery Readiness is `ready` only when every required local unit and the Global Skeleton have fresh PASS records. Sealing and Code completion require readiness; a local PASS cannot hide a global failure.

## Recovery

Recover in this order:

```text
delivery-graph.json
→ compile views/state
→ validate component and global records/transcripts
→ validate generated Proof Contract + seal
→ validate Code fingerprint
→ run metadata → evidence JSONL → anchors
→ regenerate Verification → deterministic finalization
```

Missing or stale references return only the affected unit, contract, Code, or run claim to pending. `--all-reviews` is an explicit destructive reset of review claims, not the normal resume path.

## Schema-v9 import

The only legacy boundary is `upgrade_v9_to_v10.py`. Preview is read-only. Apply archives old artifacts byte-for-byte, verifies every SHA-256 before cleanup, derives untrusted candidate nodes, and invalidates every old review, seal, Code, run, PASS, and finalization claim. Schema-v9 creation and execution are not part of v0.6.
