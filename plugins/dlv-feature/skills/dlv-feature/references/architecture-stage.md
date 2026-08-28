# Architecture graph stage

## Goal

Represent verified system facts, singular ownership, boundaries, state transitions, decisions, and risks without duplicating product truth or prematurely writing implementation details.

## Build the subgraph

1. Inspect repository evidence only as needed. Search results are candidates; read code/schema/tests before asserting a `Fact`.
2. Create one `Owner` for each authoritative fact family. Connect `Owner owns Fact/Boundary/StateTransition/Decision`; one protected truth must not have multiple owners. Every `Fact` declares `attributes.persistence`. Use `kind=database` with a schema-focused `schema_sql`; use `external/ephemeral/none` with a concrete rationale. Never leave `kind=unknown` after import reconciliation.
3. Create `Boundary` for authorization, tenant/product/lifecycle, projection, lineage/source, or write-entry constraints. Connect it with `guards` to every protected StateTransition or behavior.
4. Create `StateTransition` for each material lifecycle mutation. It needs exactly one guarding Boundary and one `transitions` target Fact/Decision.
5. Create `Decision` only when implementation must not rediscover a choice. Derive it from verified Fact/product dependencies.
6. Create `Risk` with severity and concrete failure statement. Critical/major risk needs an explicit `mitigates` edge from a Decision, Change, Test, or Proof.
7. Encode repository/path/symbol evidence in node attributes. Do not copy a schema table or API matrix into Markdown; the generated Architecture is a view of graph claims.
8. Compile and inspect the generated view. Fix missing or wrong graph claims.

## Gate

`STATE_AND_ATOMICITY` and `BOUNDARY_AND_CONCURRENCY` enforce exact ownership, Fact persistence, executable database DDL with column meaning, guards, transitions, and risk links. The database contract contains schema intent, not repository migration numbers or procedural migration code. Stable Claims bind invariants and failure boundaries; independent review challenges second sources of truth, unsafe concurrency/tenant/authorization, ambiguous lineage, compatibility, and failure modes.

A PASS freezes only the exact Architecture component and its upstream dependencies. Owner, Boundary, StateTransition, critical/major Risk, or shared context changes also require a fresh Global Skeleton PASS.
