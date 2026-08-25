# Schema v11 artifact contracts

## Delivery Graph and Scope Revision

`delivery-graph.json` is the sole editable delivery-design truth. It has
`schema_version: 11`, `feature_id`, `title`, `source_revision`, `nodes`,
`edges`, `prototype`, and `metadata.risk_vector`. Node and edge schemas remain
typed and acyclic. `source_revision` names a confirmed immutable `SRC-*`
record; any pending source record is `SOURCE_DRIFT` and blocks Ready.

The source capture has title, description, comments, attachment descriptors,
R0 risk vector, owner, timestamp, and a SHA-256 over captured content. Its
status is `confirmed` or `pending_confirmation`; only
`scope_revision.py confirm` may start a new epoch.

Risk axes are `API_CONTRACT`, `PERSISTENCE`, `AUTHORIZATION`, `TENANCY`,
`MONEY`, `CONCURRENCY`, `IRREVERSIBLE_SIDE_EFFECT`, `CROSS_CLIENT`, and
`VISUAL_CONTRACT`, each `absent`, `present`, or `critical`. R0/R1/R2 combine
monotonically; observed code may escalate but not lower prior risk.

Prototype modes are:

- `reference` with `path=prototype.html` and SHA-256;
- `contractual` with the same fields and visual Proof for every applicable
  Acceptance/Exception;
- `not_applicable` with a concrete `reason`.

## Generated state

`state.json` contains references only: Graph and stage hashes, component
attestations, Source Revision status, R0/R1/R2/effective risk, Finding Ledger
reference, convergence state, durable execution checkpoint, Proof Contract,
Code fingerprint, and Verification state. It never embeds Graph nodes,
evidence, or generated Markdown.

Architecture, Code Spec, PRD, diagrams, and Proof Contract draft are generated
from the same Graph compilation. They are not separately editable or approved.

## Reviews and Findings

Each attestation binds `(lens, stable component roots, component hash, source
revision, reviewer contract)`. The Global Skeleton always reviews cross-unit
ownership, boundaries, state transitions, material risks, source revision, and
claim synopsis. Shared providers are dependency context, not a reason to merge
unrelated components.

`.dlv/findings/{feature}/ledger.json` owns stable `FND-*` Finding identity.
Each entry contains unit, severity, evidence, risk path, root cause, first/last
scope epoch, lifecycle status, and any Owner decision. Reviewers must address
all active Findings in their unit; omission keeps it active. New Major/Critical
entries need evidence, root cause, risk path, and why prior Review could not
see them. Duplicate root causes merge.

Only `OPEN` and `FIXED_PENDING_REVIEW` block. `ACCEPTED_RISK` is rejected for
tenancy, authorization, money, and irreversible side effects.
An implementer marks a repaired Finding `FIXED_PENDING_REVIEW` with concrete
repair evidence; only the next independent Review may mark that same `FND-*`
`VERIFIED`.

## Proof and finalization

Proof Contract remains generated and one-way sealed. Every active Proof has a
declared environment, runner, target, assertion oracle, and fresh runtime
evidence. Proof strength must match its claim: artifact/typecheck evidence
cannot prove money, concurrency, or irreversible-side-effect safety; sequential
tests cannot prove concurrency safety.

Ready requires the latest confirmed Source Revision, fresh PASS attestations,
zero critical and non-waivable major blockers, no active blocking Finding, a
matching Code fingerprint, and fresh runtime Proof. Formal commits use
`DLV-Feature: <feature-id>` and cannot coexist with `Code=pending`.

Schema v10 import archives mutable artifacts byte-for-byte, retains historical
evidence unmodified, and starts v11 with no promoted completion claim.
