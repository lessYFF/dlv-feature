# Verification stage

## Start

1. Materialize one JSON file per sealed Environment, exactly matching its structured spec.
2. Start a unique run. The kernel checks the sealed contract, current Code fingerprint, Environment equality, and executes every preflight command.
3. A failed preflight creates a blocked run. Fix the environment or credentials; do not change business code to counterfeit availability.

## Record

For each Proof, provide only:

```json
{"po_id":"PO-001","proof_type":"boundary","outcome":"evaluate","anchors":[]}
```

The recorder executes the sealed runner with bounded time/output, derives observation from its adapter, evaluates every Assertion oracle, copies bounded anchors, hashes them, and appends a chained record. The caller cannot submit command output, observation, assertion status, evidence status, or verdict.

Before executing a runner, the recorder writes a pending-execution marker. If the runner may have executed but its durable evidence journal cannot be written, the run fails closed and cannot execute that Proof again; start a new Verification Run after reconciling possible side effects. This ambiguity also blocks finalization.

A failed/blocked record stays in history. Rerun with `--supersedes EVID-xxxx`; supersession must reference the same Proof and can happen once. Every Proof ultimately needs exactly one active passed record.

- `visual`: the caller supplies no screenshot labels. The sealed `visual_bundle` runner returns exact `anchor_paths`, the sealed Prototype SHA, and exact capture profile; the recorder snapshots those distinct Prototype/Implementation/Diff PNGs and recomputes pixel and geometry metrics before evaluating exact zero assertions.
- `runtime`: actual target runtime, complete action, non-empty result readback, one matching runtime-trace anchor.
- `boundary`: direct allow/deny entry probes plus zero side effect/projection/lineage observations.
- `invariant`: observe database/service state, not only HTTP success.
- `artifact`: verify the real build/config/output/health artifact.

## Finalize

`verification.md` is generated from the run and may be deleted/rebuilt. Finalization validates contract/Code/Environment freshness, preflight anchors, contiguous append-only IDs, hash-chain head/count, anchor hashes/sizes, supersession, exact active Proof coverage, and assertion results. It writes completed PASS and a token only after these checks, then performs final validation.

Only `DELIVERY COMPLETE` is completion. Local hashes detect accidental/ordinary rewriting; use signed remote attestation when an actor able to rewrite the kernel and every local artifact is in scope.
