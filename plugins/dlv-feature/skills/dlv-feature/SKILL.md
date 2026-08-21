---
name: dlv-feature
description: Run a repository-agnostic, proof-carrying feature delivery workflow from requirement review through approved UI prototype, architecture, implementation-ready Code Spec, code changes, target-runtime Verification Runs, and deterministic finalization. Use when Codex is asked to develop, implement, deliver, verify, or resume a feature end to end while preventing requirement drift, stale evidence, boundary bypasses, environment misdiagnosis, and unsupported completion claims.
---

# DLV Feature

Deliver one feature through one truth chain:

```text
Requirement Review approval → PRD ↔ Prototype product approval
→ Architecture → Architecture Quality Review → human approval
→ Code Spec + Proof Contract draft → Code Spec Quality Review → human approval
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
7. Require `schema_version=8`. For an existing v7 delivery, preview and then apply the conservative upgrade:

   ```bash
   python3 <skill-dir>/scripts/upgrade_v7_to_v8.py <feature-id> --root <project-root>
   python3 <skill-dir>/scripts/upgrade_v7_to_v8.py <feature-id> --root <project-root> --apply
   ```

   The upgrade preserves documents and raw evidence, but never promotes v7 approvals, quality verdicts, Proof Contract seals, PASS, or finalization into v8.

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

.dlv/reviews/{feature-id}/{review-run-id}.json  # immutable quality-review record
```

Do not hand-edit run metadata, the manifest, or generated Verification. Do not create parallel matrices, capsules, checklists, snapshots, or informal evidence ledgers.

Formal Markdown uses concise Chinese titles, a TOC before numbered sections, and only applicable sections. Architecture database shape uses commented fenced `sql` schema DDL: columns, types, null/default, constraints and indexes. It must not contain migration execution machinery such as `DO`, `EXECUTE`, loops, tenant iteration, DML, schema creation/drop, or migration numbering.

## Stage Routing

| State | Guide | Output |
|---|---|---|
| `prd` | [prd-stage.md](references/prd-stage.md) | `prd.md`; optional approved Prototype |
| `architecture` | [architecture-stage.md](references/architecture-stage.md) | `architecture-design.md` |
| `code_spec` | [code-spec-stage.md](references/code-spec-stage.md) | `code-spec.md` + sealed Proof Contract |
| `code` | [implementation-stage.md](references/implementation-stage.md) | repository changes |
| `verification` | [verification-stage.md](references/verification-stage.md) | Verification Run + generated `verification.md` |

Visible UI work also reads [prototype-stage.md](references/prototype-stage.md) during PRD. Follow [workflow.md](references/workflow.md) for transitions and [artifact-contracts.md](references/artifact-contracts.md) for schemas.

## Human confirmations

Every confirmation writes an exact fingerprint-bound receipt. Hash the actual confirmation text, never a paraphrase supplied by the agent:

```bash
python3 <skill-dir>/scripts/approve_stage.py requirement_review <feature-id> --root <project-root> --approved-by <identity> --approval-reference <ref> --approval-text-sha256 <sha256>
python3 <skill-dir>/scripts/approve_stage.py product <feature-id> --root <project-root> --approved-by <identity> --approval-reference <ref> --approval-text-sha256 <sha256>
```

The Product command approves the final PRD and either the exact Prototype or an explicit not-applicable decision. Architecture and Code Spec confirmations occur only after their quality reviews, as described below.

## Proof Contract

Each `PO-*` has exactly one proof type (`visual`, `runtime`, `boundary`, `invariant`, or `artifact`), one `ENV-*`, explicit upstream `trace_ids`, and one or more `ASRT-*` assertions. Each assertion has a description and structured oracle (`kind`, JSON-pointer `source`, `operator`, and expected value where applicable). Free-text `expected` and caller-supplied assertion status are not a contract.

Each `ENV-*` contains a structured target spec and executable preflight commands. Architecture and Code Spec each require an independent quality review before human approval. Review findings use `ARQ-*` or `CSQ-*`; open critical/major findings forbid `PASS`:

```bash
python3 <skill-dir>/scripts/quality_review.py architecture <feature-id> --root <project-root> --run-id <run-id> --result /abs/review.json
python3 <skill-dir>/scripts/approve_stage.py architecture <feature-id> --root <project-root> --approved-by <identity> --approval-reference <ref> --approval-text-sha256 <sha256>
python3 <skill-dir>/scripts/quality_review.py code_spec <feature-id> --root <project-root> --run-id <run-id> --result /abs/review.json
python3 <skill-dir>/scripts/approve_stage.py code_spec <feature-id> --root <project-root> --approved-by <identity> --approval-reference <ref> --approval-text-sha256 <sha256>
```

The Code Spec approval binds the exact Code Spec, quality review, and Proof Contract draft, and authorizes implementation within that scope. Then seal once without accepting new approval arguments:

```bash
python3 <skill-dir>/scripts/seal_proof_contract.py <feature-id> --root <project-root>
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

3. Execute the strongest applicable check through the recorder. Result JSON contains only `po_id`, `proof_type`, `outcome=evaluate|blocked`, optional `blocked_reason`, and optional extra file anchors; command argv/cwd/adapter are immutable fields of the sealed PO runner. Do not provide command, command results, observation, PASS/FAIL, assertion results, or supersession claims in the result file. The recorder executes the sealed runner with a bounded timeout/output capture, derives observation, resolves each oracle source, and computes the verdict.
4. Append it through the recorder; the recorder assigns `EVID-*`, copies anchors, hashes them, and never rewrites history:

   ```bash
   python3 <skill-dir>/scripts/verification_run.py record <feature-id> \
     --root <project-root> --run-id <run-id> --result /abs/result.json
   ```

5. A rerun must explicitly supersede the failed evidence for the same PO. This preserves history while removing ambiguity:

   ```bash
   ... record ... --supersedes EVID-0001
   ```

6. Start immediately generates a pending or blocked `verification.md`; render can refresh the active report during iteration. The finalizer always regenerates it:

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
- Use exactly four delivery confirmation points: requirement review; final PRD plus Prototype decision; Architecture after a fresh PASS Architecture Quality Review; Code Spec plus Proof Contract draft after a fresh PASS Code Spec Quality Review. The fourth confirmation authorizes implementation within the bound scope. External mutations still require their own authorization.
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
python3 <skill-dir>/scripts/validate_feature.py <feature-id> --root <project-root> --final
```

Finish only when all stages are fresh, every contracted assertion has current passing evidence, boundary/runtime missions pass, and no open blocker remains. Report changed code, executed checks, residual risks, and artifact paths; never claim deployment without deployment evidence.
