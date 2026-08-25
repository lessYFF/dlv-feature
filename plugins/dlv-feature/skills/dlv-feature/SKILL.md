---
name: dlv-feature
description: Run a repository-agnostic, proof-carrying feature delivery workflow from requirements through implementation and target-runtime verification. Use for end-to-end feature delivery that needs dependency-scoped review reuse, global system-coherence checks, generated contracts, and deterministic completion evidence.
---

# DLV Feature

Use one editable Delivery Graph and continuously compute delivery readiness:

```text
Delivery Graph change
→ deterministic dependency components
→ review only stale local components
→ review the compact global system skeleton when it changes
→ generated PRD / Architecture / Code Spec / Proof Contract
→ Code fingerprint → target-runtime evidence → deterministic finalization
```

Do not turn Architecture and Code Spec into serial approval stages. They are generated views. Local changes pay local review cost; changes to owners, boundaries, state transitions, critical/major risks, shared facts, or shared environments also pay the global-coherence cost.

## Canonical truth

`delivery/{feature-id}/delivery-graph.json` is the only editable machine truth. `prototype.html` is additionally editable when the graph declares a completed Prototype. Every other delivery artifact is generated or machine-maintained. Never repair generated views by hand or copy their facts into another matrix or ledger.

Read [artifact-contracts.md](references/artifact-contracts.md) before editing the graph. Use the relevant view guide while adding nodes:

- Product truth: [prd-stage.md](references/prd-stage.md)
- Architecture truth: [architecture-stage.md](references/architecture-stage.md)
- Implementation and proof truth: [code-spec-stage.md](references/code-spec-stage.md)
- Prototype: [prototype-stage.md](references/prototype-stage.md)
- Code: [implementation-stage.md](references/implementation-stage.md)
- Runtime evidence: [verification-stage.md](references/verification-stage.md)

## Workflow

Initialize or resume:

```bash
python3 <skill-dir>/scripts/init_feature.py <feature-id> --root <project-root> --title "Feature title"
python3 <skill-dir>/scripts/delivery_graph.py compile <feature-id> --root <project-root>
```

After any graph change, compile. Compilation computes deterministic review units, retains only exact fresh attestation references, refreshes the compact Global Skeleton, renders the three human views, and updates Delivery Readiness.

Run every stale review unit in parallel:

```bash
python3 <skill-dir>/scripts/quality_review.py <feature-id> --root <project-root> --run-id <run-id>
```

Each local attestation binds `(lens, component_id, component_hash, reviewer contract)`. Component boundaries are computed from graph edges; callers cannot declare them. The global attestation covers system ownership, boundaries, state transitions, critical/major risks, shared context, and a compact synopsis of cross-component product/architecture claims. A critical/major deterministic issue, failed semantic check, reviewer `BLOCKED`, or open critical/major finding blocks readiness.

Resume with exact invalidation:

```bash
python3 <skill-dir>/scripts/invalidate_downstream.py <feature-id> --root <project-root>
```

Use `--changed-node NODE-ID` for a semantic change that graph bytes cannot reveal. Use `--all-reviews` only when intentionally discarding all review claims.

When Delivery Readiness is `ready`, seal and implement:

```bash
python3 <skill-dir>/scripts/seal_proof_contract.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/delivery_graph.py mark-code-complete <feature-id> --root <project-root>
```

Then execute the generated Proof Contract in declared target environments:

```bash
python3 <skill-dir>/scripts/verification_run.py start <feature-id> --root <project-root> --run-id <run-id> --environment ENV-001=/path/to/env.json
python3 <skill-dir>/scripts/verification_run.py record <feature-id> --root <project-root> --run-id <run-id> --result /path/to/runner-result.json
python3 <skill-dir>/scripts/finalize_delivery.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/validate_feature.py <feature-id> --root <project-root> --final
```

Full operational details are in [workflow.md](references/workflow.md).

## Schema-v9 import boundary

New deliveries are schema v10 only. For an existing schema-v9 delivery, preview and explicitly apply the one-way import:

```bash
python3 <skill-dir>/scripts/upgrade_v9_to_v10.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/upgrade_v9_to_v10.py <feature-id> --root <project-root> --apply
```

The importer archives every legacy artifact byte-for-byte as an untrusted candidate, verifies its SHA-256 before cleanup, derives candidate graph nodes, and promotes no old review, seal, Code, Verification, PASS, or finalization claim. Older delivery engines remain available from their released Git tags; schema v10 does not carry their active runtime.

## Completion rule

Claim completion only when final validation reports zero errors. No prose claim, generated-looking document, cached review, caller-supplied screenshot label, or process exit alone can replace a fresh attestation, sealed contract, Code fingerprint, target-runtime evidence, and deterministic finalization.
