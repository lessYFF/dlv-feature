# Execution assessment

Record one assessment when a DLV invocation reaches a terminal result: `DELIVERY_READY`,
`failed`, `blocked`, or `cancelled`. This is append-only telemetry, not another
delivery gate. It must not trigger Review, ask the Owner for data, mutate the
Delivery Graph, or delay the terminal response when collection is unavailable.

`first_pass` means the first complete runnable candidate before product or
acceptance correction. One `rework_round` is one consolidated correction batch
after that candidate; several edits for the same batch count once. A
`process_failure` consumes time without improving the product, such as state,
credential, budget, format, or recovery failure.

## Record

Prepare a bounded JSON input from facts already available to the host. Use
`null` rather than estimating unavailable measurements.

```json
{
  "result": "DELIVERY_READY",
  "context": {
    "acceptance_items": 300,
    "surfaces": ["web", "api"],
    "contract_sensitive": true,
    "visual_applicable": true
  },
  "quality": {
    "first_pass": {
      "passed": 285,
      "total": 300,
      "critical_passed": 4,
      "critical_total": 4
    },
    "final": {
      "functional": {"passed": 100, "total": 100},
      "visual_interaction": {"passed": 99, "total": 100},
      "edge_experience": {"passed": 100, "total": 100}
    },
    "critical_requirements": {"passed": 4, "total": 4},
    "hard_failures": {
      "p0_p1_open": 0,
      "forbidden_scope_changes": 0,
      "missing_evidence": 0
    }
  },
  "efficiency": {
    "time_to_first_candidate_seconds": 600,
    "total_duration_seconds": 1200,
    "rework_rounds": 1,
    "product_correction_batches": 1,
    "process_failures": 0,
    "process_waste_seconds": 0,
    "process_interventions": 0,
    "input_tokens": null,
    "baseline": {
      "time_to_first_candidate_seconds": 600,
      "total_duration_seconds": 1200,
      "rework_rounds": 1,
      "product_correction_batches": 1,
      "process_failures": 0,
      "process_waste_seconds": 0,
      "process_interventions": 0
    }
  },
  "diagnosis": {
    "findings": [
      {"id": "obs-001", "stage": "source_capture", "evidence": "Exact observed fact"}
    ],
    "primary_finding_id": "obs-001"
  }
}
```

For a non-applicable final dimension, use an explicit reason:

```json
{"status": "not_applicable", "reason": "No user-visible surface changed."}
```

Record it once:

```bash
python3 <skill-dir>/scripts/execution_assessment.py <feature-id> --root <project-root> \
  record --run-id <run-id> --input /abs/assessment-input.json
```

Publishing is non-blocking and write-once: concurrent use creates one complete
record and rejects duplicates without waiting on an advisory lock. Each record
has a self-digest. Delayed feedback verifies and binds that digest so it cannot
silently attach to a damaged assessment.

The derived quality standards are first-pass completion at least 90%, first-pass
critical coverage 100%, each applicable final dimension at least 99%, final
critical coverage 100%, and zero known P0/P1, forbidden scope changes, missing
evidence, or false Ready. Efficiency passes only after quality passes, with no
more than one rework/correction batch, zero process failures/waste/interventions,
and no regression in time, rework, correction, or process waste against an
explicitly supplied comparable quality-qualified baseline. Without a baseline,
efficiency is `not_assessed`; raw facts remain available for later comparison.

`acceptance_items` is the frozen unique denominator. First-pass `total` must
equal it, and applicable final dimension totals must partition it. First-pass
and final critical totals must also match. Functional and edge-experience
dimensions always apply; visual may be `not_applicable` only when
`visual_applicable` is false.

Keep every evidenced diagnosis Finding, but choose at most one primary target:
the earliest causal error with the greatest downstream impact. Valid stages are
`source_capture`, `product_synthesis`, `implementation`, `runtime_proof`,
`review_finding`, and `state_recovery`.

## Delayed feedback

Do not rewrite the original assessment when a user, later Review, or production
discovers an escaped defect. Append one feedback event:

```json
{
  "source": "production",
  "p0": 0,
  "p1": 0,
  "p2": 1,
  "evidence": "Confirmed post-delivery observation"
}
```

```bash
python3 <skill-dir>/scripts/execution_assessment.py <feature-id> --root <project-root> \
  feedback --run-id <run-id> --feedback-id <feedback-id> --input /abs/feedback.json
```

Compare skill versions lexicographically: quality must pass first; then the
targeted failure must improve without degrading another quality dimension;
only then compare time, rework, process waste, and recorded token usage. Never
collapse quality and efficiency into one compensating score.
