#!/usr/bin/env python3
"""Create schema-v7 verification runs, append evidence, and render reports."""

from __future__ import annotations

import argparse
import json
import re
import signal
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from delivery_proof import (
    MISSING,
    append_jsonl,
    atomic_write_text,
    code_result_digest,
    exclusive_file_lock,
    evaluate_oracle,
    extract_state,
    file_digest,
    load_json,
    load_manifest,
    proof_contract_digest,
    repository_fingerprint,
    resolve_source,
    run_dir,
    value_digest,
    validate_feature_id,
    write_state,
)

RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
DEFAULT_TIMEOUT_SECONDS = 300
MAX_CAPTURE_BYTES = 1_048_576
MAX_ANCHOR_BYTES = 10_485_760


def timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def redact_text(value: str) -> str:
    patterns = (
        (r'''(?i)(["'](?:password|passwd|token|secret|api[_-]?key)["']\s*:\s*["'])[^"']*(["'])''', r"\1[REDACTED]\2"),
        (r"(?i)(authorization:\s*bearer\s+)[^\s]+", r"\1[REDACTED]"),
        (r"(?i)((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+", r"\1[REDACTED]"),
    )
    for pattern, replacement in patterns:
        value = re.sub(pattern, replacement, value)
    return value


def descendant_pids(parent_pid: int) -> set[int]:
    """Snapshot POSIX descendants before killing the process group, including setsid children."""
    if sys.platform == "win32":
        return set()
    completed = subprocess.run(
        ["ps", "-e", "-o", "pid=", "-o", "ppid="],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False,
    )
    children: dict[int, set[int]] = {}
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and all(field.isdigit() for field in fields):
            pid, ppid = map(int, fields)
            children.setdefault(ppid, set()).add(pid)
    result: set[int] = set()
    frontier = [parent_pid]
    while frontier:
        descendants = children.get(frontier.pop(), set()) - result
        result.update(descendants)
        frontier.extend(descendants)
    return result


def run_bounded(argv: list[str], cwd: Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Execute without a shell, draining pipes while retaining only bounded redacted output."""
    popen_options: dict[str, Any] = {}
    if sys.platform == "win32":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_options["start_new_session"] = True
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_options)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}

    def drain(name: str, stream: Any) -> None:
        try:
            while chunk := stream.read(8192):
                remaining = MAX_CAPTURE_BYTES - len(captured[name])
                if remaining > 0:
                    captured[name].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated[name] = True
        except (OSError, ValueError):
            truncated[name] = True
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=drain, args=(name, stream), daemon=True)
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        descendants = descendant_pids(process.pid)
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
        else:
            try:
                import os

                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for pid in descendants:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if process.poll() is None:
            process.kill()
        exit_code = process.wait()
    for thread in threads:
        thread.join(timeout=2)
    for stream, thread in zip((process.stdout, process.stderr), threads):
        if thread.is_alive():
            truncated["stdout" if stream is process.stdout else "stderr"] = True
            try:
                import os

                os.close(stream.fileno())
            except OSError:
                pass
            thread.join(timeout=1)
    output: dict[str, Any] = {"exit_code": 124 if timed_out else exit_code, "timed_out": timed_out}
    for name in ("stdout", "stderr"):
        text = captured[name].decode("utf-8", errors="replace")
        if truncated[name]:
            text += f"\n[TRUNCATED at {MAX_CAPTURE_BYTES} bytes]"
        output[name] = redact_text(text)
    if timed_out:
        output["stderr"] += f"\n[TIMED OUT after {timeout_seconds} seconds]"
    return output


def validate_identity(feature_id: str, run_id: str) -> None:
    validate_feature_id(feature_id)
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("run-id must use lowercase letters, digits, dot, underscore, or hyphen")


def contract_maps(contract: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    obligations = {
        item["id"]: item for item in contract.get("obligations", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    environments = {
        item["id"]: item for item in contract.get("environments", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    return obligations, environments


def parse_environment_args(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        environment_id, separator, raw_path = value.partition("=")
        if not separator or not environment_id or not raw_path:
            raise ValueError("--environment must use ENV-nn=/path/to/environment.json")
        if environment_id in result:
            raise ValueError(f"duplicate environment input: {environment_id}")
        result[environment_id] = Path(raw_path).expanduser().resolve()
    return result


def start(feature_id: str, root: Path, run_id: str, environment_args: list[str]) -> Path:
    validate_identity(feature_id, run_id)
    root = root.expanduser().resolve()
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        return _start_locked(feature_id, root, run_id, environment_args)


def _start_locked(feature_id: str, root: Path, run_id: str, environment_args: list[str]) -> Path:
    state_path = root / "delivery" / feature_id / "state.md"
    content, state = extract_state(state_path)
    if state.get("schema_version") != 7:
        raise ValueError("verification runs require schema_version=7")
    contract = state.get("proof_contract")
    if not isinstance(contract, dict) or contract.get("status") != "completed":
        raise ValueError("proof contract must be completed and sealed before starting Verification")
    if contract.get("seal") != proof_contract_digest(contract):
        raise ValueError("proof contract seal is stale")
    contract_artifact = state_path.parent / "proof-contract.json"
    if not contract_artifact.is_file() or load_json(contract_artifact) != contract:
        raise ValueError("sealed proof-contract.json is missing or disagrees with state")
    code = state.get("stages", {}).get("code", {})
    if code.get("status") != "completed":
        raise ValueError("Code must be completed before starting Verification")
    recorded_code = code.get("result", {}).get("repository_fingerprint") if isinstance(code.get("result"), dict) else None
    current_code = repository_fingerprint(root, feature_id)
    if recorded_code != current_code:
        raise ValueError("Code fingerprint is stale; invalidate before Verification")

    _, environments = contract_maps(contract)
    supplied = parse_environment_args(environment_args)
    if set(supplied) != set(environments):
        missing = sorted(set(environments) - set(supplied))
        extra = sorted(set(supplied) - set(environments))
        raise ValueError(f"environment preflight must supply every contracted environment; missing={missing}, extra={extra}")
    snapshots: dict[str, dict[str, Any]] = {}
    for environment_id, target in environments.items():
        path = supplied[environment_id]
        actual = load_json(path)
        if actual != target.get("spec"):
            raise ValueError(f"environment {environment_id} does not match its contracted structured spec")
        snapshots[environment_id] = {
            "target": target.get("target"),
            "spec": actual,
            "digest": value_digest(actual),
            "source_sha256": file_digest(path),
        }

    destination = run_dir(root, feature_id, run_id)
    if destination.exists():
        raise ValueError(f"verification run already exists: {destination}")
    destination.mkdir(parents=True)
    preflight_results: list[dict[str, Any]] = []
    for environment_id, target in environments.items():
        for check in target.get("spec", {}).get("preflight", []):
            completed = run_bounded(check["argv"], root, int(check.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)))
            result_path = destination / "preflight" / f"{environment_id.lower()}-{check['id']}.json"
            result = {
                "environment_id": environment_id,
                "check_id": check["id"],
                "argv": check["argv"],
                "exit_code": completed["exit_code"],
                "stdout": completed["stdout"],
                "stderr": completed["stderr"],
                "timed_out": completed["timed_out"],
                "status": "passed" if completed["exit_code"] == 0 else "blocked",
            }
            atomic_write_text(result_path, json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            preflight_results.append({
                "environment_id": environment_id,
                "check_id": check["id"],
                "status": result["status"],
                "anchor": result_path.relative_to(destination).as_posix(),
                "sha256": file_digest(result_path),
            })
    metadata = {
        "schema_version": 7,
        "feature_id": feature_id,
        "run_id": run_id,
        "created_at": timestamp(),
        "contract_digest": proof_contract_digest(contract),
        "code_fingerprint": current_code,
        "environments": snapshots,
        "preflight": preflight_results,
        "preflight_verdict": "PASS" if all(item["status"] == "passed" for item in preflight_results) else "BLOCKED",
    }
    atomic_write_text(destination / "run.json", json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
    atomic_write_text(destination / "evidence.jsonl", "")

    verification = state["stages"]["verification"]
    verification.update({
        "status": "in_progress" if metadata["preflight_verdict"] == "PASS" else "blocked",
        "active_run_id": run_id,
        "run_digest": None,
        "fingerprint": None,
        "verdict": None,
        "finalization": None,
        "evidence_count": 0,
        "evidence_head": "0" * 64,
    })
    state["current_stage"] = "verification"
    state["last_updated"] = timestamp()
    write_state(state_path, content, state)
    if metadata["preflight_verdict"] != "PASS":
        raise ValueError(f"environment preflight blocked run: {destination}")
    return destination


def record(feature_id: str, root: Path, run_id: str, result_path: Path, supersedes: list[str]) -> str:
    validate_identity(feature_id, run_id)
    root = root.expanduser().resolve()
    destination = run_dir(root, feature_id, run_id)
    request = load_json(result_path)
    request_digest = value_digest({"result": request, "supersedes": supersedes})
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        with exclusive_file_lock(destination / ".run.lock"):
            recovered = recover_pending_transaction(feature_id, root, run_id, request_digest)
            if recovered is not None:
                return recovered
            return _record_locked(feature_id, root, run_id, result_path, supersedes)


def recover_pending_transaction(
    feature_id: str, root: Path, run_id: str, request_digest: str | None = None,
) -> str | None:
    """Replay an interrupted manifest/state commit while the caller holds the run lock."""
    destination = run_dir(root, feature_id, run_id)
    journal_path = destination / "pending-record.json"
    if not journal_path.is_file():
        return None
    journal = load_json(journal_path)
    record_value = journal.get("record")
    if not isinstance(record_value, dict):
        raise ValueError("pending evidence transaction is malformed")
    state_path = root / "delivery" / feature_id / "state.md"
    state_content, state = extract_state(state_path)
    verification = state.get("stages", {}).get("verification", {})
    if verification.get("active_run_id") != run_id or verification.get("status") != "in_progress":
        raise ValueError("pending evidence transaction does not belong to the active in-progress run")
    expected_count = journal.get("previous_count")
    expected_head = journal.get("previous_head")
    records = load_manifest(destination / "evidence.jsonl")
    if len(records) == expected_count:
        actual_head = records[-1].get("record_hash") if records else "0" * 64
        if actual_head != expected_head:
            raise ValueError("pending evidence transaction has a stale manifest base")
        append_jsonl(destination / "evidence.jsonl", record_value)
        records.append(record_value)
    elif len(records) != expected_count + 1 or records[-1] != record_value:
        raise ValueError("pending evidence transaction conflicts with the append-only manifest")
    if verification.get("evidence_count") == expected_count and verification.get("evidence_head") == expected_head:
        verification["evidence_count"] = expected_count + 1
        verification["evidence_head"] = record_value.get("record_hash")
        state["last_updated"] = timestamp()
        write_state(state_path, state_content, state)
    elif (
        verification.get("evidence_count") != expected_count + 1
        or verification.get("evidence_head") != record_value.get("record_hash")
    ):
        raise ValueError("pending evidence transaction conflicts with the state head")
    journal_path.unlink()
    if request_digest is not None and journal.get("request_digest") == request_digest:
        return str(record_value.get("evidence_id"))
    return None


def _record_locked(feature_id: str, root: Path, run_id: str, result_path: Path, supersedes: list[str]) -> str:
    destination = run_dir(root, feature_id, run_id)
    metadata = load_json(destination / "run.json")
    if metadata.get("preflight_verdict") != "PASS":
        raise ValueError("cannot record evidence into a preflight-blocked run")
    result = load_json(result_path)
    state_path = root / "delivery" / feature_id / "state.md"
    state_content, state = extract_state(state_path)
    verification_state = state.get("stages", {}).get("verification", {})
    if verification_state.get("active_run_id") != run_id:
        raise ValueError("evidence may only be recorded into the active Verification Run")
    if verification_state.get("status") != "in_progress":
        raise ValueError("evidence may only be recorded while Verification is in_progress")
    contract = state.get("proof_contract", {})
    obligations, _ = contract_maps(contract if isinstance(contract, dict) else {})
    contract_artifact = state_path.parent / "proof-contract.json"
    if not contract_artifact.is_file() or load_json(contract_artifact) != contract:
        raise ValueError("sealed proof-contract.json is missing or disagrees with state")
    if metadata.get("contract_digest") != proof_contract_digest(contract):
        raise ValueError("run contract is stale")
    if metadata.get("code_fingerprint") != repository_fingerprint(root, feature_id):
        raise ValueError("run code fingerprint is stale")
    po_id = result.get("po_id")
    obligation = obligations.get(po_id)
    if obligation is None:
        raise ValueError(f"unknown proof obligation: {po_id}")
    if result.get("proof_type") != obligation.get("proof_type"):
        raise ValueError("evidence proof_type does not match the obligation")
    requested_outcome = result.get("outcome", "evaluate")
    if requested_outcome not in {"evaluate", "blocked"}:
        raise ValueError("outcome must be evaluate or blocked; passed/failed are computed and skips are forbidden")
    if "status" in result:
        raise ValueError("result.status is forbidden; the recorder computes evidence status")
    if requested_outcome == "blocked" and not result.get("blocked_reason"):
        raise ValueError("blocked evidence requires blocked_reason")

    if "observation" in result:
        raise ValueError("result.observation is forbidden; the recorder derives it from command output")
    if any(field in result for field in ("command", "observation_adapter")):
        raise ValueError("command and observation_adapter are sealed in the PO runner")
    command_input = obligation.get("runner")
    if not isinstance(command_input, dict):
        raise ValueError("proof obligation has no sealed runner")
    command_cwd = (root / str(command_input.get("cwd", "."))).resolve()
    try:
        command_cwd.relative_to(root)
    except ValueError as exc:
        raise ValueError("command.cwd must stay inside the project root") from exc
    if not command_cwd.is_dir():
        raise ValueError("command.cwd must be an existing directory")
    if requested_outcome == "evaluate":
        completed = run_bounded(
            command_input["argv"], command_cwd,
            int(command_input.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
        )
        command = {
            "argv": command_input["argv"],
            "cwd": command_cwd.relative_to(root).as_posix() or ".",
            "exit_code": completed["exit_code"],
            "stdout": completed["stdout"],
            "stderr": completed["stderr"],
            "timed_out": completed["timed_out"],
        }
        adapter = command_input.get("observation_adapter")
        if adapter == "json_stdout":
            try:
                observation = json.loads(completed["stdout"])
            except json.JSONDecodeError as exc:
                observation = {"adapter_error": f"stdout is not JSON: {exc.msg}"}
            if not isinstance(observation, dict):
                observation = {"adapter_error": "stdout JSON must be an object"}
        elif adapter == "none":
            observation = {}
        else:
            raise ValueError("sealed runner observation_adapter is invalid")
    else:
        command = {"argv": command_input["argv"], "cwd": command_cwd.relative_to(root).as_posix() or ".", "exit_code": None, "stdout": "", "stderr": ""}
        observation = {"blocked_reason": result.get("blocked_reason")}
    evidence_source = {"command": command, "observation": observation}

    assertion_contract = {
        item["id"]: item for item in obligation.get("assertions", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if "assertion_results" in result:
        raise ValueError("result.assertion_results is forbidden; assertions are derived from contracted sources")
    computed_results: list[dict[str, Any]] = []
    for assertion_id, assertion in assertion_contract.items():
        actual = resolve_source(evidence_source, assertion["oracle"]["source"])
        if requested_outcome == "evaluate":
            passed = evaluate_oracle(actual, assertion["oracle"])
            assertion_status = "passed" if passed else "failed"
        else:
            assertion_status = requested_outcome
        computed_results.append({
            "assertion_id": assertion_id,
            "status": assertion_status,
            "present": actual is not MISSING,
            "actual": None if actual is MISSING else actual,
        })
    status = (
        requested_outcome if requested_outcome == "blocked"
        else ("passed" if all(item["status"] == "passed" for item in computed_results) else "failed")
    )

    existing = load_manifest(destination / "evidence.jsonl")
    current_head = existing[-1].get("record_hash") if existing else "0" * 64
    if verification_state.get("evidence_count") != len(existing) or verification_state.get("evidence_head") != current_head:
        raise ValueError("evidence manifest disagrees with the state-anchored append-only head")
    evidence_id = f"EVID-{len(existing) + 1:04d}"
    existing_ids = {item.get("evidence_id") for item in existing}
    if set(supersedes) - existing_ids:
        raise ValueError("supersedes references unknown evidence")
    already_superseded = {item for record in existing for item in record.get("supersedes", [])}
    if set(supersedes) & already_superseded:
        raise ValueError("evidence can only be superseded once")
    if any(item.get("po_id") != po_id for item in existing if item.get("evidence_id") in supersedes):
        raise ValueError("evidence may only supersede the same proof obligation")

    anchors = result.get("anchors", [])
    if not isinstance(anchors, list):
        raise ValueError("anchors must be an array")
    stored_anchors: list[dict[str, Any]] = []
    anchor_dir = destination / "anchors"
    anchor_dir.mkdir(exist_ok=True)
    generated = {
        "command.json": json.dumps(command, ensure_ascii=False, indent=2) + "\n",
        "observation.json": json.dumps(observation, ensure_ascii=False, indent=2) + "\n",
    }
    for name, payload in generated.items():
        target = anchor_dir / f"{evidence_id.lower()}-{name}"
        atomic_write_text(target, payload)
        stored_anchors.append({"path": target.relative_to(destination).as_posix(), "sha256": file_digest(target), "size": target.stat().st_size})
    for index, raw in enumerate(anchors, 1):
        source = Path(str(raw)).expanduser().resolve()
        if not source.is_file():
            raise ValueError(f"anchor does not exist: {source}")
        if source.stat().st_size > MAX_ANCHOR_BYTES:
            raise ValueError(f"anchor exceeds {MAX_ANCHOR_BYTES} bytes: {source}")
        target = anchor_dir / f"{evidence_id.lower()}-{index}-{source.name}"
        shutil.copyfile(source, target)
        target.chmod(0o600)
        stored_anchors.append({
            "path": target.relative_to(destination).as_posix(),
            "sha256": file_digest(target),
            "size": target.stat().st_size,
        })

    environment_id = obligation.get("environment_id")
    snapshot = metadata.get("environments", {}).get(environment_id)
    record_value = {
        "schema_version": 7,
        "evidence_id": evidence_id,
        "recorded_at": timestamp(),
        "po_id": po_id,
        "proof_type": result.get("proof_type"),
        "status": status,
        "contract_digest": metadata["contract_digest"],
        "code_fingerprint": metadata["code_fingerprint"],
        "environment_id": environment_id,
        "environment_digest": snapshot.get("digest") if isinstance(snapshot, dict) else None,
        "command": command,
        "assertion_results": computed_results,
        "observation": observation,
        "anchors": stored_anchors,
        "blocked_reason": result.get("blocked_reason"),
        "supersedes": supersedes,
    }
    previous_hash = existing[-1].get("record_hash") if existing else "0" * 64
    record_value["previous_hash"] = previous_hash
    record_value["record_hash"] = value_digest(record_value)
    atomic_write_text(destination / "pending-record.json", json.dumps({
        "schema_version": 7,
        "request_digest": value_digest({"result": result, "supersedes": supersedes}),
        "previous_count": len(existing),
        "previous_head": previous_hash,
        "record": record_value,
    }, ensure_ascii=False, indent=2) + "\n")
    append_jsonl(destination / "evidence.jsonl", record_value)
    verification_state["evidence_count"] = len(existing) + 1
    verification_state["evidence_head"] = record_value["record_hash"]
    state["last_updated"] = timestamp()
    write_state(state_path, state_content, state)
    (destination / "pending-record.json").unlink()
    return evidence_id


def active_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    superseded = {item for record in records for item in record.get("supersedes", [])}
    return [record for record in records if record.get("evidence_id") not in superseded]


def run_digest(destination: Path) -> str:
    return value_digest({
        "run": load_json(destination / "run.json"),
        "evidence": load_manifest(destination / "evidence.jsonl"),
    })


def md_cell(value: Any) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\r\n", "\n").replace("\n", "<br>")


def render(feature_id: str, root: Path, run_id: str) -> Path:
    validate_identity(feature_id, run_id)
    root = root.expanduser().resolve()
    destination = run_dir(root, feature_id, run_id)
    with exclusive_file_lock(root / ".dlv" / "runs" / feature_id / ".feature.lock"):
        with exclusive_file_lock(destination / ".run.lock"):
            return render_locked(feature_id, root, run_id)


def render_locked(feature_id: str, root: Path, run_id: str) -> Path:
    state = extract_state(root / "delivery" / feature_id / "state.md")[1]
    verification = state.get("stages", {}).get("verification", {})
    if verification.get("active_run_id") != run_id or verification.get("status") != "in_progress":
        raise ValueError("only the active in-progress Verification Run may render the report")
    contract = state.get("proof_contract", {})
    obligations, _ = contract_maps(contract if isinstance(contract, dict) else {})
    destination = run_dir(root, feature_id, run_id)
    metadata = load_json(destination / "run.json")
    records = load_manifest(destination / "evidence.jsonl")
    active = active_records(records)
    risks = state.get("risks", []) if isinstance(state.get("risks"), list) else []
    rows = []
    for item in active:
        assertions = ", ".join(
            f"{result.get('assertion_id')}={result.get('status')} present={result.get('present')} actual={json.dumps(result.get('actual'), ensure_ascii=False)}"
            for result in item.get("assertion_results", [])
        )
        anchors = ", ".join(f"{anchor.get('path')} sha256={anchor.get('sha256')}" for anchor in item.get("anchors", []))
        command = " ".join(item.get("command", {}).get("argv", []))
        rows.append("| " + " | ".join(md_cell(value) for value in (
            item.get("evidence_id"), item.get("po_id"), item.get("proof_type"),
            f"{item.get('environment_id')}@{str(item.get('environment_digest'))[:12]}", command,
            item.get("status"), assertions, anchors,
        )) + " |")
    trace_rows = []
    for po_id, obligation in obligations.items():
        evidence_ids = [item.get("evidence_id") for item in active if item.get("po_id") == po_id]
        trace_rows.append("| " + " | ".join(md_cell(value) for value in (
            po_id, ", ".join(obligation.get("product_ids", []) + obligation.get("trace_ids", [])),
            ", ".join(item.get("id", "") for item in obligation.get("assertions", [])),
            ", ".join(evidence_ids) or "—",
        )) + " |")
    plan_rows = ["| " + " | ".join(md_cell(value) for value in (
        po_id, item.get("proof_type"), item.get("surface"), item.get("environment_id"),
        ", ".join(assertion.get("id", "") for assertion in item.get("assertions", [])),
    )) + " |" for po_id, item in obligations.items()]
    risk_rows = ["| " + " | ".join(md_cell(item.get(key)) for key in (
        "id", "type", "severity", "status", "statement", "owner",
    )) + " |" for item in risks if isinstance(item, dict)]
    title = feature_id.replace("-", " ") + " 功能"
    content = f"""# {title} — 测试与验收报告

> 本报告由 `verification_run.py render` 从 append-only Evidence Bundle 生成，禁止手工作为真值维护。

## 目录

- [1. 验证概述](#1-验证概述)
- [2. 实现核对](#2-实现核对)
- [3. 代码审查](#3-代码审查)
- [4. 测试方案](#4-测试方案)
- [5. 执行结果](#5-执行结果)
- [6. 验收追踪](#6-验收追踪)
- [7. 问题与风险](#7-问题与风险)
- [8. 验收结论](#8-验收结论)

## 1. 验证概述

- Run：`{run_id}`
- Proof Contract：`{metadata.get('contract_digest')}`
- Code：`{metadata.get('code_fingerprint')}`
- Run digest：`{run_digest(destination)}`

## 2. 实现核对

| 项目 | 结果 |
|---|---|
| Code Spec 输入 | {state.get('stages', {}).get('code', {}).get('inputs', {}).get('code_spec')} |
| 代码结果 | {code_result_digest(state)} |
| 当前 Proof Contract | {proof_contract_digest(contract)} |

## 3. 代码审查

| 门 | 结果 |
|---|---|
| Truth / Context / Simplicity / Boundary | 由 `validate_feature.py` 确定性校验 |
| Evidence integrity | 由 `validate_verification_evidence.py` 校验 manifest、断言与锚点哈希 |

## 4. 测试方案

| 证明义务 | 类型 | Surface | 环境 | 结构化断言 |
|---|---|---|---|---|
{chr(10).join(plan_rows)}

## 5. 执行结果

| 证据 | 证明义务 | 类型 | 环境 | 命令 | 状态 | 断言结果 | 锚点 |
|---|---|---|---|---|---|---|---|
{chr(10).join(rows) if rows else '| — | — | — | — | — | blocked | 尚无证据 | — |'}

## 6. 验收追踪

| 证明义务 | 产品验收 | 断言 | 当前证据 |
|---|---|---|---|
{chr(10).join(trace_rows)}

## 7. 问题与风险

| 风险 | 类型 | 严重度 | 状态 | 描述 | Owner |
|---|---|---|---|---|---|
{chr(10).join(risk_rows) if risk_rows else '| — | residual | low | closed | 无已知未解决风险 | — |'}

## 8. 验收结论

最终裁决由 `finalize_delivery.py` 在 fresh run、全断言通过且无 open blocker 时写入；当前状态：`{state.get('stages', {}).get('verification', {}).get('verdict') or 'PENDING'}`。
"""
    output = root / "delivery" / feature_id / "verification.md"
    atomic_write_text(output, content)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    start_parser = subparsers.add_parser("start")
    start_parser.add_argument("feature_id")
    start_parser.add_argument("--root", default=".")
    start_parser.add_argument("--run-id", required=True)
    start_parser.add_argument("--environment", action="append", default=[])
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("feature_id")
    record_parser.add_argument("--root", default=".")
    record_parser.add_argument("--run-id", required=True)
    record_parser.add_argument("--result", required=True)
    record_parser.add_argument("--supersedes", action="append", default=[])
    render_parser = subparsers.add_parser("render")
    render_parser.add_argument("feature_id")
    render_parser.add_argument("--root", default=".")
    render_parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    try:
        if args.command == "start":
            print(start(args.feature_id, root, args.run_id, args.environment))
        elif args.command == "record":
            print(record(args.feature_id, root, args.run_id, Path(args.result), args.supersedes))
        else:
            print(render(args.feature_id, root, args.run_id))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
