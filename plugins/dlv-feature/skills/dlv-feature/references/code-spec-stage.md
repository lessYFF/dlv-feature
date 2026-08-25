# Implementation and Proof graph stage

## Goal

Make every planned change, symbol, test, runtime, proof, and assertion executable without repeating product or architecture decisions in prose.

## Change mapping

1. Create one `Change` per independently reviewable write scope. Connect `changes` to the exact Behavior/Fact/Boundary/StateTransition/Decision it implements.
2. Create concrete `Symbol` nodes with repository/path/symbol attributes and connect each `depends_on` its Change. Every Change needs a Symbol; no Symbol may be orphaned.
3. Keep batches in Change attributes only when useful for execution order. Dependencies, not a copied batch matrix, determine context.
4. Create `Test` nodes for observable behavior/boundary/invariant checks. Connect `tests` to exact targets and `runs_in` exactly one Environment.

## Proof mapping

1. Create reusable `Environment` nodes with `attributes.target` and structured `attributes.spec`, including executable preflight commands when needed. Preflight IDs are unique safe filename segments; every timeout is an integer from 1 through 3600 seconds.
2. Create one `Proof` per coherent user result/boundary. Set `proof_type`, `surface`, `critical`, and a sealed runner (`argv/cwd/observation_adapter/timeout_seconds`, bounded to 1–3600 seconds).
3. Connect Proof `proves` to exact Acceptance/Exception and supporting Test/Boundary/Transition/Risk targets; connect `runs_in` exactly one Environment.
4. Create structured `Assertion` nodes with `attributes.oracle`. Each Assertion `proves` exactly one Proof.
5. Every Acceptance/Exception requires both Test and Proof coverage. Choose the strongest applicable type: `visual`, `runtime`, `boundary`, `invariant`, or `artifact`. Do not downgrade for convenience.
6. A completed Prototype requires every Acceptance/Exception to declare boolean `prototype_applicable`, with at least one true value and direct visual Proof coverage for every true node.
7. Each visual Proof runs in a visual target runtime, sets exact `capture_profile={viewport,state,data,dpr,fonts}`, and has exactly one `eq 0.0` pixel-diff assertion, one `eq 0` geometry-diff assertion, and one `eq 0` forbidden-element assertion. Its `visual_bundle` runner returns the sealed Prototype SHA/profile and exact Prototype/Implementation/Diff PNG paths.

The compiler generates Code Spec and the Proof Contract draft from this graph. Never hand-edit either.

## Gate and seal

`change-traceability` checks Change/Symbol and reviewed-decision closure. `proof-coverage` checks target coverage, exact environments, runners, assertions, and risk mitigation. The independent semantic lenses check whether the proposed symbols actually implement the decision and whether the observation/oracle truly proves the claimed result.

Compile, review every stale local/global unit, then seal when Delivery Readiness is `ready`. Any bound graph or attestation change returns the contract to draft.
