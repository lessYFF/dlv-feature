#!/usr/bin/env python3
"""Validated repository capability adapter for schema-v12 deliveries.

Adapters expose commands and discovery facts; they never emit a delivery
verdict, lower a risk level, waive a Claim, or mutate the Delivery Graph.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from delivery_proof import file_digest, load_json
from runtime_evidence import DEFAULT_TIMEOUT_SECONDS, run_bounded, verify_macos_signature


CAPABILITIES = {
    "instructions", "changes", "lint", "targeted_tests", "typecheck", "build",
    "integration", "runtime", "database", "browser",
}
MAX_TIMEOUT_SECONDS = 3600
MAX_SNAPSHOT_FILES = 200_000
MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024 * 1024
MAX_SNAPSHOT_FILE_BYTES = 1024 * 1024 * 1024
MIN_SNAPSHOT_FREE_BYTES = 256 * 1024 * 1024
SHA256_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}")
DOCKER_CLEANUP_TIMEOUT_SECONDS = 30
DOCKER_CLEANUP_MAX_OUTPUT_BYTES = 4096


def validate_snapshot_budget(root: Path, temporary_parent: Path) -> None:
    files = 0
    total = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        files += len(names) + len(filenames)
        if files > MAX_SNAPSHOT_FILES:
            raise ValueError("repository snapshot exceeds the file-count budget")
        for name in filenames:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            size = path.stat().st_size
            if size > MAX_SNAPSHOT_FILE_BYTES:
                raise ValueError(f"repository snapshot file exceeds the size budget: {path.relative_to(root)}")
            total += size
            if total > MAX_SNAPSHOT_BYTES:
                raise ValueError("repository snapshot exceeds the total-byte budget")
    if shutil.disk_usage(temporary_parent).free < total + MIN_SNAPSHOT_FREE_BYTES:
        raise ValueError("repository snapshot lacks bounded temporary disk capacity")


def clone_repository_snapshot(root: Path, destination: Path, *, require_cow: bool = False) -> None:
    if sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["/bin/cp", "-cR", str(root), str(destination)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=60,
            )
        except subprocess.TimeoutExpired:
            completed = subprocess.CompletedProcess([], 124)
        if completed.returncode == 0:
            return
        raise ValueError("bounded APFS repository snapshot failed")
    elif sys.platform.startswith("linux") and Path("/bin/cp").is_file():
        try:
            completed = subprocess.run(
                [
                    "/bin/cp", "--reflink=always" if require_cow else "--reflink=auto",
                    "-a", str(root), str(destination),
                ],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=60,
            )
        except subprocess.TimeoutExpired:
            completed = subprocess.CompletedProcess([], 124)
        if completed.returncode == 0:
            return
        raise ValueError("bounded reflink repository snapshot failed")
    if require_cow:
        raise ValueError("repository adapter cannot create an isolated CoW child snapshot")
    shutil.copytree(root, destination, symlinks=True)


def copy_repository_snapshot(root: Path, destination: Path) -> None:
    validate_snapshot_budget(root, destination.parent)
    clone_repository_snapshot(root, destination)


@contextmanager
def repository_snapshot(root: Path) -> Iterator[Path]:
    """Create one bounded base snapshot for isolated per-capability CoW children."""
    with tempfile.TemporaryDirectory(prefix="dlv-adapter-base-") as raw:
        base = (Path(raw) / "repository").resolve()
        copy_repository_snapshot(root.expanduser().resolve(), base)
        yield base


def trusted_executable(name: str) -> Path:
    raw = shutil.which(name)
    if not raw:
        raise ValueError(f"missing trusted executable: {name}")
    path = Path(raw).resolve()
    current = path
    while True:
        metadata = current.stat()
        if metadata.st_uid not in {0, os.getuid()} or metadata.st_mode & 0o002:
            raise ValueError(f"trusted executable path is untrusted: {path}")
        if current.parent == current:
            break
        current = current.parent
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"trusted executable is invalid: {path}")
    return path


def resolve_oci_image(image: str) -> tuple[Path, str, Path]:
    docker = trusted_executable("docker")
    if sys.platform == "darwin":
        docker = verify_macos_signature(docker, team_id="9BNSXJN65R", identifier="docker")
    endpoint = run_bounded(
        [str(docker), "context", "inspect", "--format={{.Endpoints.docker.Host}}"],
        Path.cwd(), 10, max_capture_bytes=4096,
    )
    docker_host = endpoint["stdout"].strip()
    if endpoint["exit_code"] != 0 or endpoint["timed_out"] or not docker_host.startswith("unix://"):
        raise ValueError("macOS adapter Docker context must expose a local Unix socket")
    raw_socket = docker_host.removeprefix("unix://")
    if not raw_socket.startswith("/"):
        raise ValueError("macOS adapter Docker context Unix socket must be absolute")
    try:
        docker_socket = Path(raw_socket).resolve(strict=True)
    except OSError as exc:
        raise ValueError("macOS adapter Docker context Unix socket is unavailable") from exc
    if not stat.S_ISSOCK(docker_socket.stat().st_mode):
        raise ValueError("macOS adapter Docker context endpoint is not a Unix socket")
    completed = run_bounded(
        [str(docker), "image", "inspect", "--format={{.Id}}", image],
        Path.cwd(), 30, max_capture_bytes=4096,
    )
    identity = completed["stdout"].strip()
    if completed["exit_code"] != 0 or completed["timed_out"] or not SHA256_IMAGE.fullmatch(identity):
        raise ValueError("macOS adapter sandbox_image must already exist with a resolvable immutable image ID")
    return docker, identity, docker_socket


def cleanup_oci_container(docker: Path, cidfile: Path) -> None:
    if not cidfile.is_file():
        raise ValueError("macOS adapter container identity was not created")
    container_id = cidfile.read_text(encoding="ascii").strip()
    if not CONTAINER_ID.fullmatch(container_id):
        raise ValueError("macOS adapter container identity is invalid")

    def invoke(*arguments: str) -> dict[str, Any]:
        try:
            completed = run_bounded(
                [str(docker), *arguments], Path.cwd(), DOCKER_CLEANUP_TIMEOUT_SECONDS,
                max_capture_bytes=DOCKER_CLEANUP_MAX_OUTPUT_BYTES,
            )
        except (OSError, ValueError) as exc:
            raise ValueError("macOS adapter container cleanup command failed") from exc
        if completed["timed_out"]:
            raise ValueError("macOS adapter container cleanup command timed out")
        if "[TRUNCATED at " in completed["stdout"] or "[TRUNCATED at " in completed["stderr"]:
            raise ValueError("macOS adapter container cleanup output exceeded its bound")
        return completed

    not_found = {
        f"Error response from daemon: No such container: {container_id}",
        f"Error: No such object: {container_id}",
    }
    removed = invoke("rm", "--force", container_id)
    if removed["exit_code"] != 0 and removed["stderr"].strip() not in not_found:
        raise ValueError("macOS adapter container cleanup failed")
    probe = invoke("inspect", container_id)
    if probe["exit_code"] == 0:
        raise ValueError("macOS adapter container survived bounded cleanup")
    if probe["stderr"].strip() not in not_found:
        raise ValueError("macOS adapter container absence could not be verified")


def adapter_path(root: Path) -> Path:
    return root.expanduser().resolve() / ".dlv" / "repository-adapter.json"


def validate_adapter(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "name", "source_ref", "frontend_roots", "capabilities"}:
        raise ValueError("repository adapter must contain exactly schema_version, name, source_ref, frontend_roots, and capabilities")
    if value.get("schema_version") != 12 or not all(
        isinstance(value.get(key), str) and value[key].strip() for key in ("name", "source_ref")
    ):
        raise ValueError("repository adapter identity/schema is invalid")
    capabilities = value.get("capabilities")
    frontend_roots = value.get("frontend_roots")
    if (
        not isinstance(frontend_roots, list) or not frontend_roots
        or frontend_roots != sorted(set(frontend_roots))
        or not all(
            isinstance(item, str) and bool(Path(item).parts)
            and item == Path(*Path(item).parts).as_posix()
            and not Path(item).is_absolute() and ".." not in Path(item).parts
            for item in frontend_roots
        )
    ):
        raise ValueError("repository adapter frontend_roots must be sorted unique confined directories")
    if not isinstance(capabilities, dict) or set(capabilities) - CAPABILITIES:
        raise ValueError("repository adapter contains unknown capabilities")
    for name, command in capabilities.items():
        if (
            not isinstance(command, dict)
            or not {"argv", "cwd", "timeout_seconds", "max_output_bytes"} <= set(command)
            or set(command) - {"argv", "cwd", "timeout_seconds", "max_output_bytes", "sandbox_image"}
        ):
            raise ValueError(f"adapter capability {name} has an invalid shape")
        argv = command.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
            raise ValueError(f"adapter capability {name}.argv must be a non-empty string array")
        if not isinstance(command.get("cwd"), str):
            raise ValueError(f"adapter capability {name}.cwd must be a string")
        timeout = command.get("timeout_seconds")
        output = command.get("max_output_bytes")
        if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"adapter capability {name}.timeout_seconds is out of bounds")
        if type(output) is not int or not 1024 <= output <= 10_485_760:
            raise ValueError(f"adapter capability {name}.max_output_bytes is out of bounds")
        if "sandbox_image" in command and (
            not isinstance(command["sandbox_image"], str) or not command["sandbox_image"].strip()
        ):
            raise ValueError(f"adapter capability {name}.sandbox_image must be a string")
    return value


def load_adapter(root: Path, *, required: bool = True) -> tuple[dict[str, Any] | None, str | None]:
    path = adapter_path(root)
    if not path.is_file() or path.resolve() != path.absolute():
        if required:
            raise ValueError("missing regular .dlv/repository-adapter.json")
        return None, None
    return validate_adapter(load_json(path)), file_digest(path)


def execute_capability(
    root: Path, adapter: dict[str, Any], capability: str, snapshot_base: Path | None = None,
) -> dict[str, Any]:
    """Execute one sealed parameter-array command with bounded output."""
    root = root.expanduser().resolve()
    command = adapter.get("capabilities", {}).get(capability)
    if not isinstance(command, dict):
        raise ValueError(f"repository adapter has no {capability} capability")
    cwd = (root / command["cwd"]).resolve()
    try:
        cwd.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"adapter capability {capability} cwd escapes project root") from exc
    with tempfile.TemporaryDirectory(prefix="dlv-adapter-") as raw:
        isolated_root = (Path(raw) / "repository").resolve()
        if snapshot_base is None:
            copy_repository_snapshot(root, isolated_root)
        else:
            snapshot_base = snapshot_base.expanduser().absolute()
            if snapshot_base.is_symlink() or not snapshot_base.is_dir() or snapshot_base.resolve() != snapshot_base:
                raise ValueError("repository adapter base snapshot is invalid")
            clone_repository_snapshot(snapshot_base, isolated_root, require_cow=True)
        isolated_cwd = isolated_root / cwd.relative_to(root)
        argv = command["argv"]
        command_cwd = isolated_cwd
        sandbox_image_id: str | None = None
        if sys.platform == "darwin":
            image = command.get("sandbox_image")
            if not isinstance(image, str) or not image.strip():
                raise ValueError(f"macOS adapter capability {capability} requires a preinstalled sandbox_image")
            docker, image_id, docker_socket = resolve_oci_image(image)
            sandbox_image_id = image_id
            cidfile = Path(raw) / "container.cid"
            relative_cwd = isolated_cwd.relative_to(isolated_root).as_posix()
            argv = [
                str(docker), "run", "--rm", "--network=none", "--pids-limit=256",
                "--cpus=4", "--memory=4g", "--memory-swap=4g", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges",
                f"--user={os.getuid()}:{os.getgid()}",
                "--tmpfs=/tmp:rw,nosuid,nodev,size=512m",
                "--cidfile", str(cidfile),
                "--mount", f"type=bind,src={isolated_root},dst=/workspace",
                "--workdir", f"/workspace/{relative_cwd}" if relative_cwd != "." else "/workspace",
                "--entrypoint", command["argv"][0], image_id, *command["argv"][1:],
            ]
            command_cwd = isolated_root
        try:
            result = run_bounded(
                argv, command_cwd,
                command.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
                max_capture_bytes=command["max_output_bytes"],
                allow_process_tree=sys.platform == "darwin",
                writable_roots=[Path(raw)] if sys.platform == "darwin" else [isolated_root],
                read_protected=[root],
                allowed_unix_sockets=[docker_socket] if sys.platform == "darwin" else None,
            )
        finally:
            if sys.platform == "darwin":
                cleanup_oci_container(docker, cidfile)
    return {
        "capability": capability, "command": command,
        "sandbox_image_id": sandbox_image_id, "result": result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capability", choices=sorted(CAPABILITIES))
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).expanduser().resolve()
        adapter, digest = load_adapter(root)
        output = execute_capability(root, adapter or {}, args.capability)
        print(json.dumps({"adapter_sha256": digest, **output}, ensure_ascii=False, sort_keys=True))
        return 0 if output["result"]["exit_code"] == 0 and not output["result"]["timed_out"] else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
