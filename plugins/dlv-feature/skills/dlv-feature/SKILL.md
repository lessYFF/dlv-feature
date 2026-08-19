---
name: dlv-feature
description: Run a repository-agnostic, proof-carrying feature delivery workflow from requirement review through approved UI prototype, architecture, implementation-ready Code Spec, code changes, target-runtime mission checks, and deterministic finalization. Use when Codex is asked to develop, implement, deliver, verify, or resume a feature end to end while preventing requirement drift, prototype-to-code mismatch, stale evidence, boundary bypasses, environment misdiagnosis, and unsupported completion claims.
---

# DLV Feature

Deliver one feature through one truth chain:

```text
Requirement Review → PRD ↔ Prototype (optional) → Architecture Convergence Review → Technical Solution → Code Spec → Code → Verification
```

Keep responsibilities separate:

- PRD defines product behavior.
- An approved Prototype is implementation truth for visible content, states, interaction shape, and visual geometry; it does not dictate components, APIs, state management, or architecture.
- Technical Solution makes system-level decisions.
- Code Spec maps approved decisions to files, symbols, rules, batches, and `PO-*` proof obligations.
- Verification records actual evidence and verdict.
- Deterministic scripts own invalidation and completion; an agent or document cannot self-award `completed`.

Use one minimal proof kernel:

```text
Truth → Obligation → Evidence → Verdict
```

- **Truth**: fresh fingerprints for approved PRD, Prototype, Architecture, Code Spec, code result, and runtime environment.
- **Obligation**: each `AC/EX` maps to one or more `PO-*` of exactly one type: `visual`, `runtime`, `boundary`, `invariant`, or `artifact`.
- **Evidence**: each `EVID-*` records an exact execution, observed result, anchor, proof type, and `truth/code/env` fingerprints; Code is recomputed from the Git worktree and env from the frozen target-environment string.
- **Verdict**: only `PASS` may complete; `failed`, `blocked`, `stale`, and approved non-critical skips remain explicit.

Enforce five hard gates throughout:

- **Truth Gate**: facts are `candidate`, `verified`, `proposed`, or `gap`; plausibility never promotes a candidate.
- **Context Gate**: load only the current decision, referenced anchors, bounded files, and direct dependencies.
- **Simplicity Gate**: Delete → KISS → DRY → Responsibility → Dependency; KISS wins over ceremonial SOLID.
- **Boundary Proof Gate**: every critical fact whose access, ownership, lineage, output exposure, lifecycle, or reuse changes has one `BP-*` proof: exact entrypoints, complete authorization expression, Service-side guard before writes, version/source selector and forbidden sources, denied projection, and direct negative/runtime probes.
- **Evidence Integrity Gate**: every PASS cites one exact check and observed result; ID ranges, generic success labels, planned checks, and stale evidence never count.
- **Mission Gate**: every critical user action runs in its target runtime at the strongest applicable evidence level; source search, mocks, build success, and DOM presence cannot substitute for a native side effect or integrated outcome.

Before drafting a Technical Solution, enforce one architecture convergence rule: reuse does not need permission to exist; every new table, field, API, state, Service, Policy/interface, event, or queue must prove why the current fact owner and public contract cannot be safely reused or extended. Do not draft detailed design while fact ownership, bypass writes, fail-open isolation, rule dispatch, or material decisions remain unresolved.

## Start or Resume

1. Treat the current directory as project root unless the user names another root.
2. Read applicable `AGENTS.md`, `CLAUDE.md`, repository rules, and only the indexes needed to locate evidence.
3. Resolve the feature ID:
   - resume an existing `delivery/{feature-id}/state.md`;
   - validate an explicit lowercase hyphen-case ID;
   - otherwise derive a short ID and tell the user.
4. Initialize a new feature:

   ```bash
   python3 <skill-dir>/scripts/init_feature.py <feature-id> --root <project-root>
   ```

5. Before trusting state, invalidate changed artifacts and downstream proof:

   ```bash
   python3 <skill-dir>/scripts/invalidate_downstream.py <feature-id> --root <project-root>
   ```

6. Read the JSON state block in `state.md`; then load only the current guide and its direct inputs.
7. Follow [workflow.md](references/workflow.md) for review gates, proof obligations, fingerprints, stale propagation, and recovery.
8. Require `schema_version=6`. Earlier schemas lack the proof kernel and finalization token; never auto-promote their approvals or evidence. For v5, preview the conservative recovery and obtain approval before applying it:

   ```bash
   python3 <skill-dir>/scripts/upgrade_v5_to_v6.py <feature-id> --root <project-root>
   python3 <skill-dir>/scripts/upgrade_v5_to_v6.py <feature-id> --root <project-root> --apply
   ```

   The upgrade preserves earlier truth where safe, marks Prototype or Code Spec and downstream stale, and requires a new Proof Contract plus fresh Verification.

## Core Artifacts

Persist only:

```text
delivery/{feature-id}/
├── state.md
├── prd.md
├── architecture-design.md
├── code-spec.md
├── verification.md
└── prototype.html     # only for visible UI work
```

Do not create request, matrix, manifest, capsule, checklist, snapshot, test-plan, or evidence sidecars. Keep large screenshots, visual diffs, logs, and traces in the existing test/CI artifact store; record stable anchors and hashes in `verification.md`. Merge essential semantics according to [artifact-contracts.md](references/artifact-contracts.md).

Formal Markdown documents use concise Chinese titles, a table of contents before numbered body sections, and content-driven optional sections. Never add chapter 0, an applicability matrix, a Context Capsule, or empty N/A chapters. Omission must be safe from the actual requirement and evidence; unknown applicable behavior remains a gap.

Write for review, not as a transcript. Start each numbered section with its conclusion, then use tables for mappings/comparisons, lists for steps or independent items, and diagrams for relationships or state changes. Keep prose paragraphs focused on one claim; never collapse a whole section into one dense paragraph.

## Stage Routing

Load exactly one guide at a time:

| State | Guide | Main output |
|---|---|---|
| `prd` | [prd-stage.md](references/prd-stage.md) | requirement review + `prd.md`; optional prototype experiment |
| `architecture` | [architecture-stage.md](references/architecture-stage.md) | `architecture-design.md` |
| `code_spec` | [code-spec-stage.md](references/code-spec-stage.md) | `code-spec.md` |
| `code` | [implementation-stage.md](references/implementation-stage.md) | repository changes |
| `verification` | [verification-stage.md](references/verification-stage.md) | `verification.md` |

When visible UI work is confirmed during PRD, read [prototype-stage.md](references/prototype-stage.md) as a PRD subflow. Do not treat Prototype as an independent product-truth stage.

## Evidence Rules

- Product truth priority: current user confirmation → current PRD → maintained product docs → observed behavior.
- Implementation truth priority: code/schema/tests/Git → build/CI → maintained technical docs → recollection.
- Cite technical decisions with repository, baseline, path, and symbol/contract anchor.
- Search finds candidates. Source confirmation creates verified facts.
- Only `verified` and evidence-backed `proposed` targets may enter an implementation batch or write scope.
- Critical `gap` blocks the affected stage; never invent limits, fields, roles, paths, interfaces, or defaults.
- Compute `stages.code.result.repository_fingerprint` from the real Git worktree when Code completes; never accept a self-reported commit, branch, or result label as code freshness proof.
- Classify proof by the claimed outcome, not by the convenient tool. Visual parity requires same-condition screenshots and diff; browser behavior requires browser runtime; native clipboard/share requires target native runtime; authorization and data ownership require direct integrated probes.
- Freeze each PO target environment in the Proof Contract. Evidence must reproduce that exact environment string and its SHA-256; a well-formed but unrelated env hash is stale evidence.
- Reject PASS when any PO still has failed, blocked, stale, or unapproved skipped evidence, even if another row passed.
- A critical `PO-*` cannot be manual, conditional, or skipped. A non-critical skip requires an explicit approved reason and never proves another obligation.
- Run environment preflight before diagnosing business code. Tool/runtime incompatibility, network, credentials, ports, build outputs, and target configuration produce `blocked`, never a fake business fix or PASS.
- Preserve unrelated user changes and never use destructive Git operations to simplify delivery.

## Context Budget

- Candidate repositories: at most 3.
- Candidate paths: at most 20.
- Per implementation batch: at most 8 source reads and 4 test/config/support reads.
- Dependency expansion: 1 relationship hop by default.
- Failure excerpts: at most 200 relevant lines.

When a budget is exceeded: delete irrelevant candidates, split the batch, then allow a justified expansion that names the evidence relationship. Never persist a second machine-readable capsule; the batch in `code-spec.md` is the human/machine execution boundary.

## Authorization and State

- Documentation writes stay under `delivery/{feature-id}/`.
- Require explicit approval for requirement review, final PRD, material/irreversible architecture decisions, Code Spec, product-code scope, durable test assets, and external mutations as defined by the stage guides.
- Keep the approved Code Spec immutable; reconcile actual changes in `verification.md`.
- Store only compact status, requirement-review baseline, architecture-review decision packet, artifact/direct-input fingerprints, prototype contract summary, `PO-*` proof contract, blockers, approvals, code result, Simplicity results, finalization record, and timestamps in the `state.md` JSON block.
- Use SHA-256 fingerprints. A changed direct input makes completed downstream stages stale.
- When the user changes approved behavior, explicitly run `invalidate_downstream.py --from-stage <stage>` before continuing. Never reuse evidence whose truth, code, or environment fingerprint changed.
- Recover from disk:

  ```text
  state.md → current artifact → referenced upstream anchors → repository evidence
  ```

- Validate after durable document transitions and before final handoff:

  ```bash
  python3 <skill-dir>/scripts/validate_feature.py <feature-id> --root <project-root>
  ```

- For a focused failure, run the deterministic gate directly against `delivery/{feature-id}`:

  ```bash
    python3 <skill-dir>/scripts/validate_boundary_proofs.py delivery/{feature-id}
  python3 <skill-dir>/scripts/validate_verification_evidence.py delivery/{feature-id}
  ```

## Completion

Finish only when PRD, Architecture, Code Spec, and Code are completed; Prototype is completed or `not_applicable`; every critical `PO-*` has fresh matching evidence; actual changes remain inside approved dependency closure; target-runtime missions and delivery health pass; and all hard gates are green.

Never edit Verification to `completed` directly. Set its verdict to `PASS`, keep status `in_progress`, then use the only completion entrypoint:

```bash
python3 <skill-dir>/scripts/finalize_delivery.py <feature-id> --root <project-root>
```

The finalizer validates first, writes a token bound to current truth/code/environment-facing evidence, validates again, and restores the original state on failure. `CONDITIONAL` is not a completion verdict.

Summarize changed code, executed verification, residual gaps, and artifact paths. Never claim deployment or release without evidence.
