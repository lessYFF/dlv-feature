# Prototype branch

Use this branch only when visible UI shape is product truth.

1. Read the target repository design rules and the actual page, shell, route, components, responsive constraints, and fonts.
2. Build one self-contained `prototype.html` that expresses the graph’s applicable Behavior/Acceptance/Exception states. It does not define code architecture.
3. Exercise it with the repository-configured browser capability; do not download a browser runtime solely for testing.
4. Resolve mismatches by changing the product graph when requirement truth changed, or the Prototype when only presentation was wrong.
5. Set boolean `attributes.prototype_applicable` on every Acceptance and Exception. At least one must be `true`; each true node needs direct visual Proof coverage.
6. Set:

   ```json
   {"status":"completed","path":"prototype.html","sha256":"<sha256>"}
   ```

7. Recompile and run Product review.

The final visual Proof must declare exact `capture_profile={viewport,state,data,dpr,fonts}`. Its sealed runner uses that profile and returns the Prototype SHA plus exact `anchor_paths` for distinct Prototype, Implementation, and Diff PNGs. The caller cannot label screenshots. The recorder snapshots runner-produced files, recomputes pixel and geometry metrics, and requires the sealed zero-difference assertions. Source/DOM presence is not visual proof.
