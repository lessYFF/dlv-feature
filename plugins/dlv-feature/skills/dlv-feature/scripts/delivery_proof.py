#!/usr/bin/env python3
"""Deterministic proof-kernel helpers for delivery schema v9 and Verification schema v8."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

STATE_START = "<!-- DLV_STATE_START -->"
STATE_END = "<!-- DLV_STATE_END -->"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PO_ID = re.compile(r"^PO-[0-9]+$")
ASSERTION_ID = re.compile(r"^ASRT-[0-9]+$")
ENVIRONMENT_ID = re.compile(r"^ENV-[0-9]+$")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
FEATURE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PRODUCT_ID = re.compile(r"^(?:AC|EX)-[0-9]+$")
TRACE_ID = re.compile(
    r"^(?:(?:AC|EX|FR|BR|ARCH|FLOW|API|DATA|UI|IMPACT|BP)-[0-9]+|"
    r"R-D[0-9]{2,}-[0-9]+|T-B[0-9]{2,}-[0-9]+|B[0-9]{2,}|D[0-9]{2,}|"
    r"(?:CONTRACT|SHAPE)-[A-Za-z0-9][A-Za-z0-9-]*)$"
)
PROOF_TYPES = {"visual", "runtime", "boundary", "invariant", "artifact"}
VISUAL_RUNTIMES = {"browser", "chromium", "firefox", "webkit", "wechat-devtools", "wechat-device", "ios", "android"}
RUNTIME_RUNTIMES = VISUAL_RUNTIMES | {
    "api", "service", "node", "java", "jvm", "python", "ruby", "go", "dotnet",
    "postgres", "mysql", "sqlite", "redis", "native",
}
PROFILE_ADAPTERS = {
    "visual": {"visual_bundle"},
    "runtime": {"runtime_trace"},
    "boundary": {"json_stdout", "none"},
    "invariant": {"json_stdout", "none"},
    "artifact": {"json_stdout", "none"},
}
ORACLE_KINDS = {
    "exit_code", "http_status", "json_path", "text", "file_hash",
    "screenshot_diff", "side_effect", "state",
}
OPERATORS = {"eq", "ne", "contains", "not_contains", "matches", "exists", "absent", "lte", "gte"}
MISSING = object()


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validate_feature_id(feature_id: str) -> None:
    if not FEATURE_ID.fullmatch(feature_id):
        raise ValueError("feature-id must use lowercase letters, digits, and single hyphens")


def value_digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_fingerprint(root: Path, feature_id: str) -> str:
    """Hash source state while excluding delivery records and generated run evidence."""
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise ValueError("project root must be a readable Git worktree to fingerprint Code")
    excluded = ("delivery/", ".dlv/")
    paths = sorted(
        value.decode("utf-8", errors="surrogateescape")
        for value in completed.stdout.split(b"\0")
        if value and not value.decode("utf-8", errors="surrogateescape").startswith(excluded)
    )
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(path.readlink().as_posix().encode("utf-8"))
        elif path.is_file():
            digest.update(b"file\0")
            digest.update(path.read_bytes())
        else:
            digest.update(b"missing\0")
        digest.update(b"\0")
    return digest.hexdigest()


def extract_state(path: Path) -> tuple[str, dict[str, Any]]:
    content = path.read_text(encoding="utf-8")
    match = re.search(
        rf"{re.escape(STATE_START)}\s*```json\s*\n([\s\S]*?)\n```\s*{re.escape(STATE_END)}",
        content,
    )
    if not match:
        raise ValueError("state.md has no valid DLV JSON block")
    state = json.loads(match.group(1))
    if not isinstance(state, dict):
        raise ValueError("state.md JSON block must be an object")
    return content, state


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def acquire_windows_lock(locking: Any, file_descriptor: int, nonblocking_mode: int) -> None:
    """Wait like POSIX flock; msvcrt.LK_LOCK otherwise gives up after about ten seconds."""
    while True:
        try:
            locking(file_descriptor, nonblocking_mode, 1)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EDEADLK}:
                raise
            time.sleep(0.05)


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Hold one cross-platform advisory lock for a verification-run transaction."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            if path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            acquire_windows_lock(msvcrt.locking, handle.fileno(), msvcrt.LK_NBLCK)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def write_state(path: Path, content: str, state: dict[str, Any]) -> None:
    replacement = f"{STATE_START}\n```json\n{json.dumps(state, ensure_ascii=False, indent=2)}\n```\n{STATE_END}"
    updated = re.sub(
        rf"{re.escape(STATE_START)}[\s\S]*?{re.escape(STATE_END)}",
        lambda _match: replacement, content, count=1,
    )
    atomic_write_text(path, updated)


def contract_payload(contract: Any) -> Any:
    if not isinstance(contract, dict):
        return contract
    return {key: value for key, value in contract.items() if key != "seal"}


def proof_contract_digest(contract: Any) -> str:
    return value_digest(contract_payload(contract))


def code_result_digest(state: dict[str, Any]) -> str:
    return value_digest(state.get("stages", {}).get("code", {}).get("result"))


def run_dir(root: Path, feature_id: str, run_id: str) -> Path:
    return root / ".dlv" / "runs" / feature_id / run_id


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_manifest(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number} must contain a JSON object")
        records.append(value)
    return records


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append one fsynced canonical record; callers never rewrite prior evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def evaluate_oracle(actual: Any, oracle: dict[str, Any]) -> bool:
    """Evaluate one contracted oracle without trusting a caller-supplied status."""
    operator = oracle.get("operator")
    expected = oracle.get("expected")
    if actual is MISSING:
        return operator == "absent"
    if operator == "eq":
        return actual == expected and type(actual) is type(expected)
    if operator == "ne":
        return actual != expected or type(actual) is not type(expected)
    if operator == "exists":
        return True
    if operator == "absent":
        return False
    if operator == "contains":
        try:
            return expected in actual
        except (TypeError, ValueError):
            return False
    if operator == "not_contains":
        try:
            return expected not in actual
        except (TypeError, ValueError):
            return False
    if operator == "matches":
        try:
            return isinstance(actual, str) and re.search(str(expected), actual) is not None
        except re.error:
            return False
    if operator == "lte":
        try:
            return actual <= expected and type(actual) is type(expected)
        except TypeError:
            return False
    if operator == "gte":
        try:
            return actual >= expected and type(actual) is type(expected)
        except TypeError:
            return False
    return False


def resolve_source(document: dict[str, Any], source: str) -> Any:
    """Resolve an RFC-6901-style pointer from recorder-owned command/observation data."""
    if not source.startswith("/") or not source.startswith(("/command/", "/observation/")):
        raise ValueError("oracle.source must start with /command/ or /observation/")
    value: Any = document
    for raw in source.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
            value = value[int(token)]
        else:
            return MISSING
    return value


def validate_proof_contract(
    contract: Any,
    acceptance_ids: set[str],
    code_spec_fingerprint: Any,
    prototype_completed: bool,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    location = "proof_contract"
    if not isinstance(contract, dict):
        errors.append(f"{location} must be an object")
        return {}
    if contract.get("status") not in {"pending", "completed", "stale", "blocked"}:
        errors.append(f"{location}.status is invalid")
    if contract.get("status") != "completed":
        errors.append(f"{location} must be completed before Code or Verification can complete")
    if contract.get("code_spec_fingerprint") != code_spec_fingerprint:
        errors.append(f"{location}.code_spec_fingerprint is stale")
    if contract.get("seal") != proof_contract_digest(contract):
        errors.append(f"{location}.seal does not match the immutable contract payload")
    if not isinstance(contract.get("sealed_at"), str) or not contract["sealed_at"].strip():
        errors.append(f"{location}.sealed_at is required")
    quality_review = contract.get("quality_review")
    review_fields = (
        "status", "review_run_id", "artifact_sha256", "proof_contract_sha256",
        "verdict", "record_sha256",
    )
    if not isinstance(quality_review, dict) or not all(
        isinstance(quality_review.get(key), str) and quality_review[key].strip() for key in review_fields
    ):
        errors.append(f"{location}.quality_review requires the passed Code Spec quality-review record")
    elif quality_review.get("status") != "completed" or quality_review.get("verdict") != "PASS":
        errors.append(f"{location}.quality_review must be a completed PASS")
    elif any(not SHA256.fullmatch(quality_review[field]) for field in ("artifact_sha256", "proof_contract_sha256", "record_sha256")):
        errors.append(f"{location}.quality_review contains an invalid SHA-256 fingerprint")
    elif not isinstance(quality_review.get("bound_artifacts"), dict) or any(
        not isinstance(value, str) or not SHA256.fullmatch(value)
        for value in quality_review["bound_artifacts"].values()
    ):
        errors.append(f"{location}.quality_review.bound_artifacts is invalid")

    environments = contract.get("environments")
    environment_map: dict[str, dict[str, Any]] = {}
    if not isinstance(environments, list) or not environments:
        errors.append(f"{location}.environments must be a non-empty array")
    else:
        for index, item in enumerate(environments):
            prefix = f"{location}.environments[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{prefix} must be an object")
                continue
            environment_id = item.get("id")
            if not isinstance(environment_id, str) or not ENVIRONMENT_ID.fullmatch(environment_id):
                errors.append(f"{prefix}.id must use ENV-nn")
                continue
            if environment_id in environment_map:
                errors.append(f"duplicate environment: {environment_id}")
                continue
            if not isinstance(item.get("spec"), dict) or not item["spec"]:
                errors.append(f"{prefix}.spec must be a non-empty object")
            elif not isinstance(item["spec"].get("preflight"), list) or not item["spec"]["preflight"]:
                errors.append(f"{prefix}.spec.preflight must declare executable environment checks")
            else:
                for check_index, check in enumerate(item["spec"]["preflight"]):
                    check_prefix = f"{prefix}.spec.preflight[{check_index}]"
                    if not isinstance(check, dict) or not isinstance(check.get("id"), str) or not SAFE_NAME.fullmatch(check["id"]):
                        errors.append(f"{check_prefix} requires id and argv")
                    elif not isinstance(check.get("argv"), list) or not check["argv"] or not all(isinstance(value, str) and value for value in check["argv"]):
                        errors.append(f"{check_prefix}.argv must be a non-empty string array")
                    elif "timeout_seconds" in check and (not isinstance(check["timeout_seconds"], int) or not 1 <= check["timeout_seconds"] <= 3600):
                        errors.append(f"{check_prefix}.timeout_seconds must be an integer from 1 to 3600")
            if not isinstance(item.get("spec"), dict) or not isinstance(item.get("spec", {}).get("runtime"), str):
                errors.append(f"{prefix}.spec.runtime must be concrete")
            if not isinstance(item.get("target"), str) or not item["target"].strip():
                errors.append(f"{prefix}.target must be concrete")
            environment_map[environment_id] = item

    obligations = contract.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        errors.append(f"{location}.obligations must be a non-empty array")
        return {}
    result: dict[str, dict[str, Any]] = {}
    coverage: set[str] = set()
    assertion_ids: set[str] = set()
    has_visual = False
    for index, item in enumerate(obligations):
        prefix = f"{location}.obligations[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        obligation_id = item.get("id")
        if not isinstance(obligation_id, str) or not PO_ID.fullmatch(obligation_id):
            errors.append(f"{prefix}.id must use PO-nn")
            continue
        if obligation_id in result:
            errors.append(f"duplicate proof obligation: {obligation_id}")
            continue
        result[obligation_id] = item
        product_ids = item.get("product_ids")
        if not isinstance(product_ids, list) or not product_ids:
            errors.append(f"{prefix}.product_ids must be a non-empty array")
        else:
            valid = {value for value in product_ids if isinstance(value, str) and PRODUCT_ID.fullmatch(value)}
            if len(valid) != len(product_ids) or valid - acceptance_ids:
                errors.append(f"{prefix}.product_ids contains unknown or invalid AC/EX IDs")
            coverage |= valid
        proof_type = item.get("proof_type")
        if proof_type not in PROOF_TYPES:
            errors.append(f"{prefix}.proof_type must be one of {', '.join(sorted(PROOF_TYPES))}")
        has_visual = has_visual or proof_type == "visual"
        if not isinstance(item.get("critical"), bool):
            errors.append(f"{prefix}.critical must be boolean")
        if not isinstance(item.get("surface"), str) or not item["surface"].strip():
            errors.append(f"{prefix}.surface must be concrete")
        trace_ids = item.get("trace_ids")
        if not isinstance(trace_ids, list) or not trace_ids or not all(isinstance(value, str) and value.strip() for value in trace_ids):
            errors.append(f"{prefix}.trace_ids must be a non-empty explicit array")
        elif not all(TRACE_ID.fullmatch(value) for value in trace_ids):
            errors.append(f"{prefix}.trace_ids contains an invalid or ranged ID")
        if "expected" in item:
            errors.append(f"{prefix}.expected is forbidden; use structured assertions")
        if item.get("environment_id") not in environment_map:
            errors.append(f"{prefix}.environment_id must reference a contracted ENV-*")
        environment = environment_map.get(item.get("environment_id"), {})
        runtime = environment.get("spec", {}).get("runtime") if isinstance(environment, dict) else None
        if proof_type == "visual" and runtime not in VISUAL_RUNTIMES:
            errors.append(f"{prefix} visual proof requires a browser, developer-tool, or device runtime")
        if proof_type == "runtime" and runtime not in RUNTIME_RUNTIMES:
            errors.append(f"{prefix} runtime proof cannot use a build-only runtime")
        runner = item.get("runner")
        if not isinstance(runner, dict):
            errors.append(f"{prefix}.runner must bind argv, cwd, and observation_adapter")
        else:
            argv = runner.get("argv")
            if not isinstance(argv, list) or not argv or not all(isinstance(value, str) and value for value in argv):
                errors.append(f"{prefix}.runner.argv must be a non-empty string array")
            if not isinstance(runner.get("cwd"), str) or not runner["cwd"].strip():
                errors.append(f"{prefix}.runner.cwd must be concrete")
            if runner.get("observation_adapter") not in PROFILE_ADAPTERS.get(str(proof_type), set()):
                errors.append(f"{prefix}.runner.observation_adapter does not match proof_type={proof_type}")
            if "timeout_seconds" in runner and (not isinstance(runner["timeout_seconds"], int) or not 1 <= runner["timeout_seconds"] <= 3600):
                errors.append(f"{prefix}.runner.timeout_seconds must be an integer from 1 to 3600")
        assertions = item.get("assertions")
        if not isinstance(assertions, list) or not assertions:
            errors.append(f"{prefix}.assertions must be a non-empty array")
            continue
        for assertion_index, assertion in enumerate(assertions):
            assertion_prefix = f"{prefix}.assertions[{assertion_index}]"
            if not isinstance(assertion, dict):
                errors.append(f"{assertion_prefix} must be an object")
                continue
            assertion_id = assertion.get("id")
            if not isinstance(assertion_id, str) or not ASSERTION_ID.fullmatch(assertion_id):
                errors.append(f"{assertion_prefix}.id must use ASRT-nn")
            elif assertion_id in assertion_ids:
                errors.append(f"duplicate assertion: {assertion_id}")
            else:
                assertion_ids.add(assertion_id)
            if not isinstance(assertion.get("description"), str) or not assertion["description"].strip():
                errors.append(f"{assertion_prefix}.description must be concrete")
            oracle = assertion.get("oracle")
            if not isinstance(oracle, dict):
                errors.append(f"{assertion_prefix}.oracle must be an object")
                continue
            if oracle.get("kind") not in ORACLE_KINDS:
                errors.append(f"{assertion_prefix}.oracle.kind is invalid")
            if oracle.get("operator") not in OPERATORS:
                errors.append(f"{assertion_prefix}.oracle.operator is invalid")
            if not isinstance(oracle.get("source"), str) or not oracle["source"].startswith(("/command/", "/observation/")):
                errors.append(f"{assertion_prefix}.oracle.source must select command or observation data")
            if oracle.get("operator") not in {"exists", "absent"} and "expected" not in oracle:
                errors.append(f"{assertion_prefix}.oracle.expected is required")
        assertion_sources = {
            item.get("oracle", {}).get("source") for item in assertions if isinstance(item, dict)
        }
        if proof_type == "visual":
            required_sources = {
                "/observation/pixel_diff_ratio",
                "/observation/geometry_diff_max",
                "/observation/forbidden_elements_count",
            }
            if not required_sources <= assertion_sources:
                errors.append(f"{prefix} visual assertions must cover pixel, geometry, and forbidden-element results")
            visual_oracles = {
                assertion.get("oracle", {}).get("source"): assertion.get("oracle", {})
                for assertion in assertions if isinstance(assertion, dict)
            }
            for source in sorted(required_sources):
                oracle = visual_oracles.get(source)
                if not isinstance(oracle, dict) or oracle.get("operator") != "eq" or oracle.get("expected") != 0:
                    errors.append(f"{prefix} visual assertion {source} must require exact zero difference")
        if proof_type == "runtime" and "/observation/result_readback" not in assertion_sources:
            errors.append(f"{prefix} runtime assertions must prove /observation/result_readback")

    missing = acceptance_ids - coverage
    if missing:
        errors.append(f"proof obligations do not cover acceptance IDs: {', '.join(sorted(missing))}")
    if prototype_completed and not has_visual:
        errors.append("visible UI with a reviewed prototype requires at least one visual proof obligation")
    return result


def finalization_payload(state: dict[str, Any]) -> dict[str, Any]:
    stages = state.get("stages", {})
    verification = stages.get("verification", {})
    return {
        "schema_version": state.get("schema_version"),
        "feature_id": state.get("feature_id"),
        "truth": {name: stages.get(name, {}).get("fingerprint") for name in ("prd", "prototype", "architecture", "code_spec")},
        "quality_reviews": value_digest(state.get("quality_reviews", {})),
        "code_result": code_result_digest(state),
        "proof_contract": proof_contract_digest(state.get("proof_contract")),
        "run_id": verification.get("active_run_id"),
        "run_digest": verification.get("run_digest"),
        "verification": verification.get("fingerprint"),
        "verdict": verification.get("verdict"),
        "risks": value_digest(state.get("risks", [])),
        "finalization": {
            "tool": verification.get("finalization", {}).get("tool") if isinstance(verification.get("finalization"), dict) else None,
            "finalized_at": verification.get("finalization", {}).get("finalized_at") if isinstance(verification.get("finalization"), dict) else None,
        },
    }


def finalization_token(state: dict[str, Any]) -> str:
    return value_digest(finalization_payload(state))


def validate_finalization(state: dict[str, Any], errors: list[str]) -> None:
    verification = state.get("stages", {}).get("verification", {})
    if verification.get("status") != "completed":
        return
    record = verification.get("finalization")
    if not isinstance(record, dict):
        errors.append("completed verification requires finalize_delivery.py finalization record")
        return
    if record.get("tool") != "finalize_delivery.py" or not isinstance(record.get("finalized_at"), str):
        errors.append("verification finalization record is invalid")
    if record.get("token") != finalization_token(state):
        errors.append("verification finalization token is stale or was not generated by current inputs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fingerprint = subparsers.add_parser("repository-fingerprint")
    fingerprint.add_argument("feature_id")
    fingerprint.add_argument("--root", default=".")
    args = parser.parse_args()
    if args.command == "repository-fingerprint":
        print(repository_fingerprint(Path(args.root).expanduser().resolve(), args.feature_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
