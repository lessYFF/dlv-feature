# Code stage

Implement only after Delivery Readiness is `ready` and the generated Proof Contract is sealed.

1. Load the Change/Symbol dependency closure for the next bounded unit plus repository instructions and direct source/test dependencies.
2. Verify proposed paths/symbols against the current repository. If actual work changes product behavior, ownership, boundary, state transition, proof strength, or write scope, update the graph and re-run only affected lenses before coding.
3. Write the smallest failing test where practical, make it pass with the minimum implementation, and run relevant regression checks.
4. Review the diff for unmapped files/symbols, new entry points, authorization/tenant/source bypasses, migrations/config/secrets, error handling, and Proof runner executability.
5. Prefer Delete → KISS → DRY → Responsibility → Dependency. Do not add speculative interfaces, factories, or duplicate truth.
6. Environment/tool failure is blocked work, not a reason to change business behavior.
7. When implementation and project-native tests are complete, record Code through:

   ```bash
   python3 <skill-dir>/scripts/delivery_graph.py mark-code-complete <feature-id> --root <project-root>
   ```

The kernel fingerprints tracked and untracked source while excluding `delivery/` and `.dlv/`. Any later source drift invalidates Code and Verification only; graph attestations remain reusable if their subgraphs are unchanged.
