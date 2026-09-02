# Schema v13 artifact contracts

## Editable truth

`delivery/{feature}/delivery-graph.json` is the sole editable delivery truth.
It contains `schema_version: 13`, feature/source identity, current Product Lock
reference, `claims`, typed nodes and edges, Delivery Prototype declaration, risk vector, Review budget, and delivery
mode. Generated Markdown, state, reviews, ledgers, contracts, and evidence are
derived records and must not be repaired by hand.

`source-anchors.json` is a deterministic generated view. It splits immutable
Source text and UTF-8 attachment content into stable clause Anchors and
classifies normative requirements, decisions, prohibitions, states, errors,
and artifact structure. Product truth cites Anchor IDs; humans never maintain
this file.

Every non-cryptographic Source attachment embeds `content`,
`content_encoding`, and `size_bytes`; `sha256` is recomputed from those bytes.
A locator may document provenance but cannot substitute for captured content.
Binary attachments always receive a critical whole-attachment Anchor. Product
Alignment additionally requires `extracted_text` plus `extraction_adapter`
from a format-aware parser/OCR step; otherwise the workflow blocks for
extraction or an explicit Owner decision instead of claiming silent coverage.

`state.json.subject_reconciliation` compares Graph Symbol paths with the full
implementation baseline-to-current repository delta, including deletions,
ordinary later commits, tracked worktree changes, and untracked paths.
Every observed path must map to a planned Symbol and every planned Symbol must
bind at least one observed path before Code can complete.
`risk_frontier` groups critical Claims by independent failure boundary and
active generic risk axes. `critical_experiments` binds reusable,
content-addressed PASS evidence to the current frontier, Claims, Subjects,
Proof runner, Assertions, Environment, and Graph digest. The kernel executes
the sealed runner, evaluates the oracle and target attestation, and signs the
record; caller-authored PASS JSON is never accepted as experiment evidence.

`state.json.delivery_status` is `AUTHORING`, `REVIEWABLE`, or
`DELIVERY_READY`. Only the final value is a completion claim.

Each Claim contains exactly `id`, `lens`, `invariant`, sorted `subjects`,
`failure_boundary`, `critical`, and sorted `proof_ids`. Its `CLM-*` identity is
the digest of lens + invariant + subjects + failure boundary + criticality. The only initial
risk lenses are `PROVENANCE_INTEGRITY`, `STATE_AND_ATOMICITY`,
`BOUNDARY_AND_CONCURRENCY`, and `RUNTIME_AUTHENTICITY`.
`claim_successions` is reserved and must remain empty. Natural-language
"strengthening" cannot deterministically prove that a new invariant or subject
set preserves an old Claim. A semantic change creates a new Claim ID and a new
obligation; the predecessor Finding remains separate and blocking until explicit
independent Review resolves it. Graph/unit repartitioning needs no succession:
unchanged Claim IDs and semantic Finding IDs already survive it.

## Source, Alignment, and Product Lock

The Graph references one confirmed immutable `SRC-*` capture. It contains typed
attachments and structured Owner decisions. Raw product prototypes remain Source
attachments. Every Requirement, Behavior, Acceptance, and Exception has non-empty
`origins`: direct source references or derived repository/platform constraints
with an explicit reason.

`prd.md` and `prototype.html` are regenerated delivery views. Delivery Prototype
is only `generated` or `not_applicable`; v13 removes `reference` and `contractual`.
Independent Product Alignment covers every product node with `PRESERVED`,
`CLARIFIED`, or `DECISION_REQUIRED` and returns only `SAFE` or `NEEDS_DECISION`.
Only SAFE seals `product-locks/PCL-<digest>.json`.

The Product Lock binds Source revision/digest, product subgraph, PRD SHA,
Delivery Prototype SHA, alignment digest/verdict, source coverage, and Owner
decision refs. Missing/freshness failure blocks Review and all downstream stages.
Product, PRD, Prototype, or Source drift invalidates every downstream attestation,
Proof Contract, Code completion, and Verification result.

## Findings and convergence

`.dlv/findings/{feature}/ledger.json` owns `FND-*`. Finding identity excludes
review-unit IDs and includes Claim, failure mode, violated invariant, sorted
subjects, and sorted risk axes. Exact matches merge deterministically and add
to `observed_in_units`. Partial semantic overlap creates a blocking
`MERGE_CANDIDATE`; text similarity alone never merges.
Resolving partial overlap is an explicit Owner decision: the superseded entry
must name one related canonical Finding. Finding IDs cannot be rebound to new
semantics, and stored semantic keys are recomputed on load.
A superseded alias may route an OPEN rediscovery to its canonical blocker, but
verification must return the canonical ID and exact canonical semantic payload.

Convergence compares:

```text
[critical_obligation_weight, nonwaivable_major_obligation_weight,
 unproven_critical_claims, major_obligation_weight, missing_proofs,
 stale_reviews, review_units]
```

OPEN and MERGE_CANDIDATE Findings weigh 2; FIXED_PENDING_REVIEW weighs 1.
Repair is therefore monotonic progress while remaining blocking until an
independent Review verifies it.

Finding severity is the delivery priority contract: `critical=P0`, `major=P1`,
`moderate=P2`, and `minor=P3`. P0/P1 cannot be accepted as delivery risk. An
OPEN P2 produces `NEEDS_DECISION` until an Owner fixes it, moves it out of
scope, or records `ACCEPTED_RISK` with a reason. P3 is advisory and may remain
OPEN without preventing Ready. Ready therefore means zero important unresolved
Findings, not zero Findings of every priority.

States are `CONVERGING`, `STABLE_BLOCKED`, `DIVERGING`, `NEEDS_DECISION`, and
`READY`. State retains the latest three distinct vectors. Two consecutive
increases in ready distance, blocking Finding count, or Review-unit count
produce divergence; one ordinary invalidation is tolerated. Exhausting
campaign, unit-review, or new-Finding budget produces `NEEDS_DECISION`, never
PASS. A prospective campaign that reaches a stop-loss is durably counted as
consumed Review work before convergence is re-derived, so the Owner-decision
gate survives validation and recompilation.
`max_campaigns` is a hard upper bound of three; configuration may lower it but
cannot raise it. A fourth automatic campaign is forbidden. After the third
non-Ready campaign, only an explicit Owner decision may choose repair,
risk acceptance for P2, scope change, or termination.
The Finding Ledger stores an independent append-only convergence event stream.
Each event carries `key_id`, an RS256 signature, an authority digest, the
previous record hash, and the exact confirmed Source Revision ID/digest. Every
load rechecks that Source Revision's authority attachment. The repository carries the public key, while the matching
private key remains external (`$CODEX_HOME/dlv-feature/convergence-rs256.pem` or
`DLV_CONVERGENCE_PRIVATE_KEY`). The confirmed Source Revision binds that public
identity. Any machine or CI can verify existing history; appending without the
matching private key fails explicitly. Rebinding the source or changing the key
invalidates the chain. Schema v13 intentionally has no in-place rotation command;
any future versioned rotation protocol must require Owner approval and preserve
prior events. The compiler and validator derive state history, previous vector,
status, budget use, and reason from that stream and current records. Ledger size
is capped at 8 MiB and convergence history at 256 events; reaching the event cap
is a hard schema-v13 terminal that requires a future versioned migration. Schema
v13 provides no manual checkpoint, truncation, rebaseline, or rotation escape hatch.

### v13 quality-contract compatibility

The 0.10 quality extension remains schema-v13 compatible. Existing locator-only
attachments can still be loaded and compiled, but their Product Lock is
deterministically classified `content_stale`; Product Alignment and completion
remain blocked until `source_capture.py` records a new immutable Source revision
that materializes the attachment bytes. Compilation regenerates the extended
state and Proof Contract views, so there is no in-place mutation of the old
Source revision and no second editable migration truth.

## Repository adapter and fast path

`.dlv/repository-adapter.json` exposes bounded parameter-array capabilities for
instruction/change discovery, lint, targeted tests, typecheck, build,
integration, runtime, database, and browser operations. It cannot decide
verdicts, lower risk, mutate Claims, or grant waiver.
On macOS every executable capability declares `sandbox_image`; the image must
already exist locally and is resolved to its immutable OCI image ID before a
network-disabled, PID/memory/CPU-limited container runs against a disposable
repository snapshot. Every capability result records that resolved image ID,
so the fast-path evidence digest exposes tag drift. Linux uses the same
snapshot under `bwrap` with a private network namespace and private `/run` and
`/tmp`, preventing host TCP/UDP, abstract-socket, and common runtime Unix-socket
access. The isolated semantic Codex process is the sole outbound-network mode:
it keeps `/run` and `/tmp` private but uses host networking for Codex HTTPS.
The `changes` capability returns exactly
`{schema_version:12, paths:[...], surfaces:[...], risk_axes:[...]}` with sorted,
unique values. `frontend_roots` and the adapter SHA are confirmed Source
Revision provenance, not adapter self-report. Only `frontend`, `frontend_test`, and `documentation` surfaces
are fast-path eligible; malformed or boundary-bearing output fails closed to
the standard route. Eligibility unions Source R0, Graph R1, and observed-code
R2 risk. The kernel freezes base/merge-base OIDs, changed paths, adapter SHA,
and Code fingerprint before capability execution. Mutation, symlinks, special
files, oversized sources, or paths outside `frontend_roots` fail closed.
Concurrent fast-path starts are serialized only long enough to reserve the
feature. The capability pipeline runs outside that lock; a crash leaves the
reservation in place and routes later starts to the standard/reconciliation
path instead of silently replaying work. A caught routine execution failure
writes a sanitized BLOCKED journal and releases only its matching reservation;
the exception message is never persisted.
Owner decision: a hard process/host crash may leave the reservation fail-closed.
This accepted P2 availability risk never weakens delivery because later starts
route to the standard path. An operator may remove the reservation only after
confirming no matching run is active; automatic stale-owner guessing is forbidden.

`frontend_fast_path` changes scheduling only. It is ineligible for API,
persistence, authorization, tenancy, money, concurrency, cross-client, or
irreversible-side-effect risk. It retains identical Source, Claim, Finding,
Proof, and Ready contracts and ends at fresh Proof required.

## Proof authenticity

The generated one-way-sealed Proof Contract binds the Product Lock SHA, Claims, obligations,
environments, runners, assertions, and Review attestations. High-strength
runtime/invariant/visual evidence binds the Code fingerprint and real Git HEAD
OID; HEAD carries the feature trailer and non-kernel source is fully committed.
It also binds build, deployment, target runtime, adapter SHA, fixture SHA, and a fresh
kernel-issued nonce unique to that evidence record. Drift or nonce reuse makes evidence stale.

Repository-controlled commands execute through an OS file sandbox that denies
the convergence credential directory and strips its locator variables. macOS
uses `sandbox-exec`: high-strength Proof commands deny child creation, while
repository-adapter process trees execute in a disposable repository copy with
the real workspace write-denied; semantic review sees only its disposable
immutable snapshot. Linux requires `bwrap` with PID isolation and a writable
working-directory bind. Without the required sandbox, execution fails closed.

Each high-strength Environment pins an RS256 target-attestation issuer,
audience, and RSA public JWK. The actual target signs nonce, target/build/
deployment identities, and the canonical measurement digest. Kernel-owned
verification rejects local echo/self-report; the runner receives the nonce but
not the expected target identity. Visual attestations also sign the three
capture hashes before the core copies and re-hashes them.

Runtime action, readback, and trace share target identity and nonce.
Boolean-only observations cannot satisfy high-strength Proof. RSA key and
compact-token sizes are bounded before verification. Critical state/concurrency
Claims require invariant/runtime Proof plus Assertions that explicitly bind
business `subject_ids`, exactly one unique authoritative measurement per subject,
and state or side-effect readback. Visual captures
come only from the sealed runner; core copies distinct Prototype,
Implementation, and Diff PNGs and recomputes pixel/geometry metrics.

Ready requires confirmed Source, a current SAFE Product Lock, fresh PASS attestations,
zero P0/P1 Findings and zero undecided P2 Findings, complete critical Claim Proof coverage, sealed
contract, matching Code fingerprint, and one active fresh passed record per
Proof. Schema v11 migration archives old mutable records and promotes no prior
seal, PASS, Ready, or Product Lock claim. v12 migration preserves original bytes
under `archive-v12` and promotes no prototype. Migration prevalidates symlinks, stages a complete
archive, and rolls back every mutated record if compilation fails.
