# Product graph stage

## Goal

Convert source requirements into explicit product nodes without inventing behavior. Product truth lives in `Requirement/Persona/Behavior/Acceptance/Exception`; `prd.md` is only their generated projection.

## Build the subgraph

1. Create one `Requirement` per independently changeable source claim. Preserve source references in `attributes` when available.
2. Create `Persona` only for a real actor boundary.
3. Create observable `Behavior` nodes and connect each with `derives_from` to its Requirement and applicable Persona.
4. Split success, negative, boundary, permission, empty, and error outcomes into independently provable `Acceptance` or `Exception` nodes. Each derives from the exact Behavior.
5. Leave a real ambiguity outside committed behavior and ask the user if it changes scope or result. Do not encode recommendations as facts.
6. If UI is visible, read [prototype-stage.md](prototype-stage.md). Otherwise keep `prototype.status=not_applicable`.
7. Compile and inspect the generated PRD for readability; fix the graph, never the Markdown.

## Gate

Run the Product review. The deterministic lens blocks missing requirements/acceptance and orphan behavior/outcomes. The independent semantic lens checks fidelity to requirements, concrete observable outcomes, negative behavior, internal consistency, and invented scope.

PASS freezes only the exact Product component. Unrelated components reuse their attestations; changing a bound product dependency invalidates only dependent units and the Global Skeleton when shared system context changed.
