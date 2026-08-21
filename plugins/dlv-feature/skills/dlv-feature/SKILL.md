---
name: dlv-feature
description: Run a repository-agnostic, proof-carrying feature delivery workflow from requirement review through approved UI prototype, architecture, implementation-ready Code Spec, code changes, target-runtime Verification Runs, and deterministic finalization. Use when Codex is asked to develop, implement, deliver, verify, or resume a feature end to end while preventing requirement drift, stale evidence, boundary bypasses, environment misdiagnosis, and unsupported completion claims.
---

# DLV Feature

Deliver one feature through one truth chain:

```text
Requirement Review → PRD ↔ Prototype → Architecture → Code Spec
→ Immutable Proof Contract → Code → Verification Run → Evidence Bundle → Verdict
```

Keep ownership singular:

- PRD owns product behavior.
- Approved Prototype owns visible content, states, interaction shape, and geometry.
- Architecture owns system decisions and fact ownership.
- Code Spec owns files, symbols, rules, batches, and proof mapping.
- The sealed Proof Contract owns target environments and executable assertions.
- A Verification Run owns one execution context.
- The append-only Evidence Bundle owns observations and hashed anchors.
- `verification.md` is generated output; it never awards PASS.
- Deterministic scripts alone invalidate and finalize.

Use this kernel:

```text
Immutable Truth → Structured Assertion → Machine Evidence → Deterministic Verdict
```

## Start or Resume

1. Treat the current directory as project root unless the user names another.
2. Read applicable repository instructions and only indexes needed to locate evidence.
3. Resolve or derive a lowercase hyphen-case feature ID.
4. Initialize when absent:

   ```bash
   python3 <skill-dir>/scripts/init_feature.py <feature-id> --root <project-root>
   ```

5. Invalidate changed artifacts and code before trusting state:

   ```bash
   python3 <skill-dir>/scripts/invalidate_downstream.py <feature-id> --root <project-root>
   ```

6. Read the JSON state block, then load only the current stage guide and direct inputs.
7. Require `schema_version=7`. For an existing v6 delivery, preview and then apply the conservative upgrade only after approval:

   ```bash
   python3 <skill-dir>/scripts/upgrade_v6_to_v7.py <feature-id> --root <project-root>
   python3 <skill-dir>/scripts/upgrade_v6_to_v7.py <feature-id> --root <project-root> --apply
   ```

   The upgrade preserves earlier product/architecture truth, stales Code Spec and downstream claims, and requires a new structured Proof Contract and fresh run.

## Artifacts

Product and design truth stays under:

```text
delivery/{feature-id}/
├── state.md
├── prd.md
├── architecture-design.md
├── code-spec.md
├── proof-contract.json  # one-way sealed approval snapshot
├── verification.md       # generated view only
└── prototype.html        # visible UI only
```

Execution evidence stays outside the truth documents:

```text
.dlv/runs/{feature-id}/{run-id}/
├── run.json
├── evidence.jsonl        # append-only, script-generated
├── preflight/*.json
└── anchors/*             # copied evidence with SHA-256
```

Do not hand-edit run metadata, the manifest, or generated Verification. Do not create parallel matrices, capsules, checklists, snapshots, or informal evidence ledgers.

Formal Markdown uses concise Chinese titles, a TOC before numbered sections, and only applicable sections. Architecture database shape must be shown with fenced `sql` DDL (`CREATE/ALTER TABLE`, constraints, and indexes); never use a Markdown field table as a schema substitute.

## Stage Routing

| State | Guide | Output |
|---|---|---|
| `prd` | [prd-stage.md](references/prd-stage.md) | `prd.md`; optional approved Prototype |
| `architecture` | [architecture-stage.md](references/architecture-stage.md) | `architecture-design.md` |
| `code_spec` | [code-spec-stage.md](references/code-spec-stage.md) | `code-spec.md` + sealed Proof Contract |
| `code` | [implementation-stage.md](references/implementation-stage.md) | repository changes |
| `verification` | [verification-stage.md](references/verification-stage.md) | Verification Run + generated `verification.md` |

Visible UI work also reads [prototype-stage.md](references/prototype-stage.md) during PRD. Follow [workflow.md](references/workflow.md) for transitions and [artifact-contracts.md](references/artifact-contracts.md) for schemas.

## Proof Contract

Each `PO-*` has exactly one proof type (`visual`, `runtime`, `boundary`, `invariant`, or `artifact`), one `ENV-*`, explicit upstream `trace_ids`, and one or more `ASRT-*` assertions. Each assertion has a description and structured oracle (`kind`, JSON-pointer `source`, `operator`, and expected value where applicable). Free-text `expected` and caller-supplied assertion status are not a contract.

Each `ENV-*` contains a structured target spec and executable preflight commands. After Code Spec approval, seal once:

```bash
python3 <skill-dir>/scripts/seal_proof_contract.py <feature-id> --root <project-root> \
  --approved-by <identity> --approval-reference <review-or-message-id>
```

Any contract mutation breaks its seal. To change it, invalidate Code Spec and create a new contract; never reseal a completed contract in place.

## Verification Run

1. Materialize each contracted environment as JSON matching its structured spec.
2. Start a unique run. The script verifies contract/code freshness and executes every preflight command:

   ```bash
   python3 <skill-dir>/scripts/verification_run.py start <feature-id> \
     --root <project-root> --run-id <run-id> \
     --environment ENV-01=/abs/env-01.json
   ```

3. Execute the strongest applicable check through the recorder. Result JSON contains only `po_id`, `proof_type`, `outcome=evaluate|blocked`, optional `blocked_reason`, optional extra file anchors, and `supersedes`; command argv/cwd/adapter are immutable fields of the sealed PO runner. Do not provide command, command results, observation, PASS/FAIL, or assertion results. The recorder executes the sealed runner with a bounded timeout/output capture, derives observation, resolves each oracle source, and computes the verdict.
4. Append it through the recorder; the recorder assigns `EVID-*`, copies anchors, hashes them, and never rewrites history:

   ```bash
   python3 <skill-dir>/scripts/verification_run.py record <feature-id> \
     --root <project-root> --run-id <run-id> --result /abs/result.json
   ```

5. A rerun must explicitly supersede the failed evidence for the same PO. This preserves history while removing ambiguity:

   ```bash
   ... record ... --supersedes EVID-0001
   ```

6. Render is optional during iteration and only accepts the active in-progress run; it shares the feature/run locks with recorder and finalizer. The finalizer always regenerates the report:

   ```bash
   python3 <skill-dir>/scripts/verification_run.py render <feature-id> --root <project-root> --run-id <run-id>
   ```

Environment/tool/network/credential failures are `blocked`, never PASS and never justification for a business-code workaround. Source search, mocks, build success, and DOM presence cannot substitute for a declared native/runtime side effect.

## Hard Gates

- Truth: candidate or gap never enters write scope.
- Context: default 3 repositories, 20 candidate paths, 8 source reads, 4 support reads, one dependency hop, and 200 relevant failure lines per batch.
- Simplicity: Delete → KISS → DRY → Responsibility → Dependency; KISS wins over ceremonial abstractions.
- Boundary: every access/owner/lineage/projection/lifecycle change has one complete `BP-*` and direct negative probe.
- Evidence: every active PO has exactly one fresh passed evidence record; skips are forbidden.
- Integrity: state and sealed contract snapshot agree; contract/code/environment digests match; every preflight summary is re-derived from its contracted command and hashed anchor; evidence hash-chain head/count match state; every anchor exists inside the run and matches SHA-256. Start, recorder, render, and finalizer share ordered cross-platform feature/run locks; a write-ahead journal replays interrupted manifest/state commits. This detects accidental or ordinary file rewriting, but does not claim to resist an attacker who can modify code, state, validator, and all local artifacts together; use an external signed/remote attestation when that threat is in scope.
- Risk: risks are structured `RISK-*`; an open blocker prevents PASS, and accepted residual risk names its approver.
- Mission: every critical action runs in its target runtime at its declared proof strength.

## Authorization and Recovery

- Documentation writes stay under `delivery/{feature-id}/`; machine run data stays under `.dlv/runs/`.
- Require explicit approval for requirement review, final PRD, material architecture decisions, Code Spec/Proof Contract, product-code scope, durable tests, and external mutations.
- Keep approved PRD, Architecture, Code Spec, and Proof Contract immutable. Plan/actual differences are evidence, not retroactive plan edits.
- Preserve unrelated user changes and avoid destructive Git operations.
- Recover from `state.md → current artifact/contract → active run → manifest/anchors → repository evidence`.

Validate durable transitions:

```bash
python3 <skill-dir>/scripts/validate_feature.py <feature-id> --root <project-root>
python3 <skill-dir>/scripts/validate_boundary_proofs.py delivery/{feature-id}
python3 <skill-dir>/scripts/validate_verification_evidence.py <feature-id> --root <project-root>
```

## Completion

Do not set Verification to completed or PASS by hand. The finalizer locks the active run, recovers any interrupted record transaction, independently validates the run, regenerates `verification.md`, binds the current contract/code/run/report into a token, validates again, and compare-and-swap restores state/report on failure without overwriting concurrent edits:

```bash
python3 <skill-dir>/scripts/finalize_delivery.py <feature-id> --root <project-root>
```

Finish only when all stages are fresh, every contracted assertion has current passing evidence, boundary/runtime missions pass, and no open blocker remains. Report changed code, executed checks, residual risks, and artifact paths; never claim deployment without deployment evidence.
