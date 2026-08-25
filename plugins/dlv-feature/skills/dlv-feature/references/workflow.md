# Schema v11 workflow

```text
capture source → confirm scope epoch → edit Graph → compile/lint
→ Review stale components + global coherence → resolve Findings
→ seal → implement → reconcile Code risk → target-runtime Proof → finalization
```

## Review depth

The universal kernel is Source Revision, minimal Graph, deterministic lint,
semantic Review, Finding Ledger, Proof Contract, Diff/evidence reconciliation,
and Ready decision. Risk activates additive lenses rather than another serial
workflow.

`UI_LOCAL` needs requirement/UI-state/component/Test/Proof traceability and
design/interaction review. It does not invent persistence, distributed state,
idempotency, or concurrency obligations. A local UI change touching money,
authorization, business-state semantics, API, persistence, tenant boundaries,
or cross-client behavior automatically becomes a higher-risk route.

## Invalidation and convergence

The compiler assigns stable component identity from typed roots, then records
dependency paths for invalidation. A changed local Symbol should retain
unrelated components and the Global Skeleton. Owner, boundary, state,
material-risk, source-revision, or cross-component topology changes refresh
global coherence.

Every campaign first verifies old Findings. New blockers need new evidence;
repeated root causes share an ID. If remaining obligations do not decline,
state becomes `STABLE_BLOCKED`; a pending scope capture or unplanned Code risk
becomes `NEEDS_DECISION`. These states stop automatic Graph mutation, never
create automatic PASS.

## Recovery

One feature lock serializes Graph/state/ledger writes. Semantic Review uses
independent temporary read-only processes. Failure preserves a checkpoint:
`needs_resume` resumes recorded work; `needs_decision` waits for an Owner
scope/design/risk decision. New source input creates drift instead of blindly
cancelling work.

Before finalization DLV reconciles formal feature commits, Code fingerprint,
effective risk, sealed Proof Contract, environments, runners, fixtures,
assertion observability, evidence anchors, and final state. Any mismatch is
pending or blocked, never Ready.
