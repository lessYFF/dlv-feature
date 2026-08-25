# Schema v10 artifact contracts

## Delivery Graph

`delivery-graph.json` is the sole editable structured truth:

```json
{
  "schema_version": 10,
  "feature_id": "feature-id",
  "title": "Feature title",
  "nodes": [
    {
      "id": "AC-001",
      "type": "Acceptance",
      "title": "Observable success",
      "statement": "The saved result is visible after refresh",
      "attributes": {"prototype_applicable": true}
    },
    {
      "id": "FACT-001",
      "type": "Fact",
      "title": "Saved result",
      "statement": "The saved result is authoritative",
      "attributes": {
        "persistence": {
          "kind": "database",
          "schema_sql": "CREATE TABLE saved_result (\n  id bigint PRIMARY KEY -- result identity\n);"
        }
      }
    },
    {
      "id": "PO-001",
      "type": "Proof",
      "title": "Target-runtime readback",
      "statement": "Execute the user action and read the saved result",
      "attributes": {
        "proof_type": "runtime",
        "surface": "Save action",
        "critical": true,
        "runner": {
          "argv": ["python3", "tests/prove_save.py", "--json"],
          "cwd": ".",
          "observation_adapter": "runtime_trace",
          "timeout_seconds": 300
        }
      }
    }
  ],
  "edges": [
    {"source": "PO-001", "type": "proves", "target": "AC-001"},
    {"source": "PO-001", "type": "runs_in", "target": "ENV-001"},
    {"source": "ASRT-001", "type": "proves", "target": "PO-001"}
  ],
  "prototype": {"status": "not_applicable"}
}
```

Node IDs use their fixed type prefix and at least three digits: `REQ/BHV/AC/EX/PER/FACT/OWN/BND/ST/DEC/RISK/CHG/SYM/TST/ENV/PO/ASRT`. Nodes contain only `id/type/title/statement/attributes`; edges contain exactly `source/type/target`. IDs and edges are unique, references exist, and the dependency graph is acyclic.

Every `Fact` declares `attributes.persistence.kind`. `database` requires schema-focused `schema_sql` with executable `CREATE TABLE` or `ALTER TABLE` DDL and a comment for each declared column. Repository migration numbers and procedural/data-changing migration logic are forbidden in this architecture contract. `external`, `ephemeral`, and `none` require a rationale. `unknown` exists only for untrusted v9 import candidates and blocks readiness until reconciled.

`prototype.status=completed` additionally requires `path=prototype.html` and its SHA-256. Every Acceptance and Exception then declares boolean `attributes.prototype_applicable`, at least one is `true`, and visual Proof edges directly cover every applicable ID. Prototype is the only non-graph editable product artifact.

## Generated views and state

`prd.md`, `architecture-design.md`, and `code-spec.md` are deterministic graph projections. They are reading views, not serial approval stages. Regenerate them with the compiler.

`state.json` contains only machine-maintained identity and references:

```json
{
  "schema_version": 10,
  "feature_id": "feature-id",
  "graph_sha256": "<sha256>",
  "node_hashes": {"AC-001": "<sha256>"},
  "stage_hashes": {
    "product": "<sha256>",
    "architecture": "<sha256>",
    "implementation_proof": "<sha256>"
  },
  "readiness": {
    "status": "ready",
    "required_units": ["fact-ownership--0123456789abcdef", "global-system-coherence"],
    "missing_units": [],
    "blocked_units": [],
    "global_skeleton_sha256": "<sha256>"
  },
  "attestations": {
    "fact-ownership--0123456789abcdef": {
      "review_run_id": "readiness-01",
      "record_path": ".dlv/reviews/feature-id/readiness-01.fact-ownership--0123456789abcdef.json",
      "record_sha256": "<sha256>",
      "subgraph_sha256": "<sha256>",
      "verdict": "PASS"
    }
  },
  "proof_contract": {
    "status": "sealed",
    "draft_sha256": "<sha256>",
    "sha256": "<sha256>",
    "seal": "<sha256>"
  },
  "code": {"status": "completed", "repository_fingerprint": "<sha256>"},
  "verification": {
    "status": "in_progress",
    "active_run_id": "run-01",
    "evidence_count": 1,
    "evidence_head": "<sha256>",
    "run_digest": null,
    "verdict": null,
    "finalization": null
  }
}
```

State never embeds nodes, graph edges, a full Proof Contract, evidence, or generated Markdown content.

## Component and global attestations

The compiler partitions each lens from graph edges; callers cannot declare a component boundary. Shared Environment and Risk nodes remain visible dependency context but do not merge unrelated Proof components merely because they use one runtime or mitigate one cross-cutting risk. Every local component and the compact `global-system-coherence` skeleton has an immutable JSON record and, in normal workflow, an immutable Codex transcript. The Global Skeleton includes a compact, hash-bound synopsis of product and architecture claims so contradictions across otherwise disconnected components remain reviewable. A record binds the exact unit/component identity, subgraph hash, covered IDs, deterministic issues, semantic findings, invocation metadata, and composite verdict:

```json
{
  "schema_version": 10,
  "feature_id": "feature-id",
  "review_run_id": "readiness-01",
  "unit_id": "fact-ownership--0123456789abcdef",
  "lens": "fact-ownership",
  "component_id": "0123456789abcdef",
  "stage": "architecture",
  "execution": {
    "mode": "isolated_process",
    "provider": "codex-exec",
    "invocation_id": "lens-...",
    "transcript_path": ".dlv/reviews/feature-id/...transcript.jsonl",
    "transcript_sha256": "<sha256>",
    "result_sha256": "<sha256>",
    "independent": true
  },
  "subgraph_sha256": "<sha256>",
  "covered_node_ids": ["FACT-001", "OWN-001"],
  "issues": [],
  "semantic_checks": [{"id": "ownership", "status": "PASS", "evidence": "OWN-001 owns FACT-001"}],
  "semantic_findings": [],
  "semantic_verdict": "PASS",
  "verdict": "PASS"
}
```

Any deterministic critical/major issue, semantic check failure, semantic `BLOCKED`, or open critical/major finding forces composite `BLOCKED`. Delivery Readiness is `ready` only when every current local component and the Global Skeleton have fresh PASS records.

## Generated and sealed Proof Contract

The compiler derives Environment, Proof, and Assertion records; they are never copied from Code Spec prose:

```json
{
  "schema_version": 10,
  "feature_id": "feature-id",
  "graph_sha256": "<sha256>",
  "subgraph_sha256": "<sha256>",
  "draft_sha256": "<sha256>",
  "status": "sealed",
  "environments": [
    {"id": "ENV-001", "target": "browser runtime", "spec": {"runtime": "browser", "preflight": []}}
  ],
  "obligations": [
    {
      "id": "PO-001",
      "product_ids": ["AC-001"],
      "trace_ids": ["TST-001"],
      "proof_type": "runtime",
      "surface": "Save action",
      "environment_id": "ENV-001",
      "critical": true,
      "runner": {"argv": ["python3", "tests/prove_save.py", "--json"], "cwd": ".", "observation_adapter": "runtime_trace"},
      "prototype_sha256": null,
      "capture_profile": null,
      "assertions": [
        {
          "id": "ASRT-001",
          "description": "Saved result is read back",
          "oracle": {"kind": "json_path", "source": "/observation/result_readback", "operator": "exists"}
        }
      ]
    }
  ],
  "attestations": {"fact-ownership--0123456789abcdef": {"record_path": "...", "record_sha256": "...", "verdict": "PASS"}},
  "sealed_at": "2026-08-25T12:00:00+08:00",
  "seal": "<sha256>"
}
```

The seal is SHA-256 over every field except `seal`. It binds all applicable attestation summaries. Graph or attestation drift regenerates a draft and removes the integrity seal.

### Trust boundary

Schema-v10 hashes, transcripts, append-only records, and seals are deterministic integrity controls for the delivery workflow. They detect accidental drift, hand edits, stale inputs, and caller-supplied computed verdicts. The normal semantic-review path runs Codex from an external temporary directory so repository instructions cannot steer the reviewer, and production sealing accepts only the exact `codex-exec` provenance/result shape.

These SHA-256 seals are not digital signatures. A principal that already has unrestricted filesystem access and can replace the Skill scripts can fabricate a new internally consistent local history. When reviewer authenticity must withstand a malicious repository writer, run review/final validation in separately controlled CI and protect its signed result or branch status outside the repository.

Proof types are `visual/runtime/boundary/invariant/artifact`. Assertions use JSON Pointer sources under `/command` or `/observation` and deterministic operators `eq/ne/contains/not_contains/matches/exists/absent/lte/gte`.

A visual Proof sets `runner.observation_adapter=visual_bundle` and exact `attributes.capture_profile={viewport,state,data,dpr,fonts}`. The generated obligation binds that profile plus the current Prototype SHA-256. Its runner stdout JSON must contain:

```json
{
  "anchor_paths": {
    "prototype_screenshot": "/runner/output/prototype.png",
    "implementation_screenshot": "/runner/output/implementation.png",
    "visual_diff": "/runner/output/diff.png"
  },
  "prototype_sha256": "<sealed prototype sha256>",
  "capture_profile": {
    "viewport": "1440x900",
    "state": "saved-result",
    "data": "fixture-v1",
    "dpr": 1,
    "fonts": ["Noto Sans SC"]
  },
  "pixel_diff_ratio": 0.0,
  "geometry_diff_max": 0,
  "forbidden_elements_count": 0
}
```

Visual PNG paths come only from this sealed runner observation. Caller-supplied visual anchor labels are rejected.

## Verification Run and evidence

`.dlv/runs/{feature-id}/{run-id}/run.json` binds schema/feature/run identity, sealed contract digest, Code fingerprint, exact Environment snapshots, and executed preflight anchors. `evidence.jsonl` is append-only. Each record binds prior hash, sealed runner result, derived observation, assertion actual/status, copied anchor paths/hashes/sizes, and explicit same-Proof supersession history.

The caller cannot provide command output, observation, assertion results, evidence status, or verdict. One active passed evidence record is required for every sealed Proof. All anchors stay inside the run and match their SHA-256 and size. `verification.md` is a disposable generated view.

## Schema-v9 import boundary

The retained importer archives every legacy source byte and emits only an untrusted candidate graph. Legacy Proof `product_ids` and `trace_ids` remain in candidate attributes for reconciliation. Only target types supported by the v10 Proof contract become `proves` edges, so broad legacy Code Spec trace lists do not become false proof dependencies. No old review, seal, Code, Verification, PASS, or finalization claim crosses the boundary.
