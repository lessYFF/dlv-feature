# Product graph stage

## Goal

Convert source requirements into explicit product nodes without inventing behavior. Product truth lives in `Requirement/Persona/Behavior/Acceptance/Exception`; `prd.md` is only their generated projection.

## Build the subgraph

1. Create one `Requirement` per independently changeable source claim. Preserve source references in `attributes` when available.
2. Create `Persona` only for a real actor boundary.
3. Create observable `Behavior` nodes and connect each with `derives_from` to its Requirement and applicable Persona.
4. Split success, negative, boundary, permission, empty, and error outcomes into independently provable `Acceptance` or `Exception` nodes. Each derives from the exact Behavior.
5. Leave a real ambiguity outside committed behavior and ask the user if it changes scope or result. Do not encode recommendations as facts.
6. Add `origins` to every Requirement, Behavior, Acceptance, and Exception.
7. If UI is visible, read [prototype-stage.md](prototype-stage.md). Otherwise keep `delivery_prototype.status=not_applicable`.
8. Compile and inspect the generated PRD for readability; fix the graph, never the Markdown.

## Gate

Generate `prd.md` and the Delivery Prototype, then run independent Product Alignment against Source. SAFE seals a Product Lock; only real ambiguity, degradation, conflict, new scope, unmapped content, or platform limitation asks the Owner.

PASS freezes only the exact Product component. Unrelated components reuse their attestations; changing a bound product dependency invalidates only dependent units and the Global Skeleton when shared system context changed.
