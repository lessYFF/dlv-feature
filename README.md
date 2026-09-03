# DLV Feature

Current plugin version: **0.11.0**, Delivery Graph schema v13.

DLV Feature is a proof-carrying Codex workflow with immutable Source Revisions, generated PRD and Delivery Prototype views, independent Product Alignment, a content-addressed Product Lock, stable Claims and semantic Findings, budgeted convergence control, target-runtime authenticity, and deterministic finalization.

Version 0.10.0 improves first-pass completeness without another manual review
loop. Source attachment bytes are materialized and digest-checked at capture.
The kernel automatically derives clause-level anchors, planned versus observed
implementation Subjects, a risk frontier, and the minimum independent critical
experiment set. Valid early experiment evidence is content-addressed and reused
by the final Proof Contract. Semantic completion is `REVIEWABLE`; only
reconciled Code plus sealed Proof plus finalized target-runtime PASS becomes
`DELIVERY_READY`.

Version 0.10.0 keeps the schema-v13 artifact format and adds deterministic,
stage-aware workflow routing. `state.json.readiness.next_action` now separates
Product authoring, prototype regeneration, Product Alignment, post-lock
Architecture/Code Spec Graph authoring, Finding repair, Quality Review, Owner
decisions, and fail-closed Lock recovery. Quality Review cannot invoke Codex or
create execution/campaign/transcript state while deterministic critical/major
authoring blockers remain. Product Alignment remains identity-safe: the reviewer
returns order-independent verdicts carrying immutable Product node and Source
anchor IDs, while the trusted kernel binds identities and derives exact
Source-to-Graph reciprocal mappings. Hosts must provision `CODEX_HOME/auth.json`
and `config.toml` as owner-controlled, single-linked regular files with permissions
no broader than `0600`; missing files and symlinks are rejected by design. A host
must verify the release digest or signature outside the plugin before loading or
executing any plugin code. Preflight reports `environment_ready` plus untrusted
diagnostic version/hash values; it never attests its own plugin identity and its
success does not authorize Product Alignment without that prior host verification.

Review is risk-gated rather than zero-Finding-gated: critical/P0 and major/P1
Findings block delivery, moderate/P2 requires an explicit Owner decision, and
minor/P3 is advisory. Automatic Review is capped at three campaigns; a third
non-Ready result moves to `NEEDS_DECISION` instead of starting another loop.

Architecture and Code Spec are generated views, not serial approval stages. A local edit invalidates only its dependency component. Owner, Boundary, StateTransition, critical/major Risk, shared Fact, or shared Environment changes also invalidate the Global Skeleton attestation.

Version 0.11.0 adds a non-blocking execution assessment after every terminal
skill outcome. It records first-pass and final quality separately from delivery
efficiency, derives false Ready instead of trusting a self-report, keeps one
primary improvement target without discarding other observed deviations, and
supports append-only escaped-defect feedback. The assessment does not alter the
Delivery Graph, add a Review, or participate in Ready gates.

## Install

```bash
codex plugin marketplace add lessYFF/dlv-feature
codex plugin add dlv-feature@dlv-feature-marketplace
```

## Core flow

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/semantic_review_preflight.py
python3 plugins/dlv-feature/skills/dlv-feature/scripts/init_feature.py feature-id --root /path/to/project --title "Feature title"
python3 plugins/dlv-feature/skills/dlv-feature/scripts/scope_revision.py feature-id --root /path/to/project capture --source /path/to/issue-source.json --owner owner
python3 plugins/dlv-feature/skills/dlv-feature/scripts/scope_revision.py feature-id --root /path/to/project confirm --revision SRC-002 --owner owner --affected-node REQ-001
python3 plugins/dlv-feature/skills/dlv-feature/scripts/delivery_graph.py compile feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/product_alignment.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/seal_product_lock.py feature-id --root /path/to/project --alignment /path/to/ALN-....json
python3 plugins/dlv-feature/skills/dlv-feature/scripts/critical_experiment.py feature-id --root /path/to/project --experiment EXP-...
python3 plugins/dlv-feature/skills/dlv-feature/scripts/quality_review.py feature-id --root /path/to/project --run-id review-01
python3 plugins/dlv-feature/skills/dlv-feature/scripts/seal_proof_contract.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/reconcile_code.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/delivery_graph.py mark-code-complete feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/verification_run.py start feature-id --root /path/to/project --run-id run-01 --environment ENV-001=/path/to/env.json
python3 plugins/dlv-feature/skills/dlv-feature/scripts/verification_run.py record feature-id --root /path/to/project --run-id run-01 --result /path/to/result.json
python3 plugins/dlv-feature/skills/dlv-feature/scripts/finalize_delivery.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/execution_assessment.py feature-id --root /path/to/project record --run-id delivery-01 --input /path/to/assessment.json
```

After each compile, honor `state.json.convergence` stop states first, then
execute `state.json.readiness.next_action`. In
particular, a SAFE Product Lock is followed by deterministic Architecture and
implementation-proof Graph authoring when needed; Quality Review starts only
when the route is `run_quality_review`. Missing/content-stale Locks route to
Product Alignment, while invalid/tampered Locks route to fail-closed recovery.

If Product Alignment returns `NEEDS_DECISION`, record only the precise Owner
answer to the reported ambiguity, degradation, conflict, new scope, unmapped
source, or platform limitation. This creates a new confirmed Source epoch:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/scope_revision.py feature-id --root /path/to/project resolve --decision-id DEC-001 --question "..." --answer "..." --reason platform_limitation --owner owner --affected-node AC-001
```

Then update the affected Graph product nodes and their `origins`, rebuild the
Delivery Prototype when UI applies, compile to regenerate the PRD, rerun Product
Alignment, and seal the replacement Product Lock. Do not use `resolve` for safe
clarifications.

Pure frontend work may use the quality-preserving fast path after configuring
`.dlv/repository-adapter.json`. On macOS each capability also needs a locally
preinstalled `sandbox_image`; the adapter resolves it to an immutable image ID
and never pulls during delivery:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/frontend_fast_path.py feature-id --root /path/to/project --run-id fast-01
```

## Import legacy deliveries

Schema v13 does not promote legacy prototypes, completion claims, or Proof into a Product Lock. Upgrade schema v12 directly:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v12_to_v13.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v12_to_v13.py feature-id --root /path/to/project --apply
```

Import schema v11 directly into the current untrusted candidate:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v11_to_v12.py feature-id --root /path/to/project
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v11_to_v12.py feature-id --root /path/to/project --apply
```

Compatibility importers for schema v9/v10 emit an untrusted v13 candidate. Import archives mutable records and invalidates all prior completion claims.

## Test

```bash
python3 -m unittest plugins/dlv-feature/skills/dlv-feature/scripts/test_delivery_graph.py
python3 -m unittest plugins/dlv-feature/skills/dlv-feature/scripts/test_quality_core.py
python3 -m unittest plugins/dlv-feature/skills/dlv-feature/scripts/test_execution_assessment.py
python3 /path/to/skill-creator/scripts/quick_validate.py plugins/dlv-feature/skills/dlv-feature
```
