#!/usr/bin/env python3
"""Bounded command and runtime-evidence helpers for schema-v13 verification."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import zlib
from pathlib import Path
from typing import Any

if sys.platform == "darwin":
    import resource
else:
    resource = None

DEFAULT_TIMEOUT_SECONDS = 300
MAX_CAPTURE_BYTES = 1_048_576
MAX_ANCHOR_BYTES = 10_485_760
MAX_VISUAL_PIXELS = 16_777_216


def verify_macos_signature(path: Path, *, team_id: str, identifier: str) -> Path:
    resolved = path.resolve()
    requirement = (
        f'anchor apple generic and certificate leaf[subject.OU] = "{team_id}" '
        f'and identifier "{identifier}"'
    )
    completed = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", f"-R={requirement}", str(resolved)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"untrusted signed macOS executable: {resolved}")
    return resolved


def trusted_sandbox_executable(name: str) -> Path | None:
    raw = shutil.which(name)
    if not raw:
        return None
    try:
        path = Path(raw).resolve(strict=True)
        current = path
        while True:
            metadata = current.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError(f"untrusted OS sandbox executable path: {path}")
            if current.parent == current:
                break
            current = current.parent
    except OSError as exc:
        raise ValueError(f"untrusted OS sandbox executable path: {raw}") from exc
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"untrusted OS sandbox executable path: {path}")
    return path


def sandboxed_argv(
    argv: list[str], cwd: Path, *, allow_process_tree: bool = False,
    deny_process_fork: bool = False,
    writable_roots: list[Path] | None = None,
    read_protected: list[Path] | None = None,
    allowed_unix_sockets: list[Path] | None = None,
    allow_outbound_process_tree: bool = False,
) -> list[str]:
    """Deny repository-controlled children access to convergence authority credentials."""
    configured = os.environ.get("DLV_CONVERGENCE_PRIVATE_KEY")
    key_path = Path(configured).expanduser() if configured else Path(
        os.environ.get("CODEX_HOME", Path.home() / ".codex")
    ).expanduser() / "dlv-feature" / "convergence-rs256.pem"
    protected = key_path.parent.resolve()
    sandbox_exec = trusted_sandbox_executable("sandbox-exec") if sys.platform == "darwin" else None
    if sandbox_exec is not None:
        hidden = [protected, *(path.resolve() for path in (read_protected or []))]
        hidden_policy = "".join(
            f'(deny file-read* file-write* (subpath {json.dumps(str(path))}))'
            for path in hidden
        )
        network_policy = "".join(
            f'(allow network-outbound (remote unix-socket (path {json.dumps(str(path.resolve()))})))'
            for path in (allowed_unix_sockets or [])
        )
        if sum((allow_process_tree, allow_outbound_process_tree, deny_process_fork)) > 1:
            raise ValueError("process-tree and process-fork policies conflict")
        if allow_outbound_process_tree:
            profile = f'(version 1)(allow default)(deny network-inbound){hidden_policy}'
        elif allow_process_tree:
            writable = [path.resolve() for path in (writable_roots or [])]
            if not writable:
                raise ValueError("macOS process trees require an explicit disposable writable root")
            write_policy = "".join(
                f'(allow file-write* (subpath {json.dumps(str(path))}))'
                for path in writable
            )
            profile = (
                f'(version 1)(deny default)'
                f'(import "/System/Library/Sandbox/Profiles/system.sb")'
                f'(allow process*)(allow file-read*)'
                f'{write_policy}{network_policy}{hidden_policy}'
            )
        elif deny_process_fork:
            profile = f'(version 1)(allow default)(deny process-fork){hidden_policy}'
        else:
            profile = f'(version 1)(allow default){hidden_policy}'
        return [str(sandbox_exec), "-p", profile, *argv]
    bwrap = trusted_sandbox_executable("bwrap") if sys.platform.startswith("linux") else None
    if bwrap is not None:
        home = str(Path.home().resolve())
        writable_cwd = str(cwd.expanduser().resolve())
        writable = [path.resolve() for path in (writable_roots or [cwd])]
        if not any(Path(writable_cwd).is_relative_to(path) for path in writable):
            raise ValueError("sandbox cwd must be contained by one explicit writable root")
        network_namespace = [] if allow_outbound_process_tree else ["--unshare-net"]
        command = [
            str(bwrap), "--unshare-pid", *network_namespace, "--die-with-parent", "--new-session",
            "--ro-bind", "/", "/", "--ro-bind", home, home,
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/run",
        ]
        for path in writable:
            command.extend(["--bind", str(path), str(path)])
        for path in [protected, *(item.resolve() for item in (read_protected or []))]:
            command.extend(["--tmpfs", str(path)])
        return [*command, "--", *argv]
    raise ValueError(
        "repository-controlled commands require an OS sandbox that denies convergence signing credentials"
    )


def is_supported_image(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError:
        return False
    return header.startswith(b"\x89PNG\r\n\x1a\n") or header.startswith(b"\xff\xd8\xff") or (len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP")


def copy_bounded_anchor(source: Path, target: Path) -> None:
    if not source.is_file():
        raise ValueError(f"anchor does not exist: {source}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    total = 0
    try:
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            while chunk := reader.read(65_536):
                total += len(chunk)
                if total > MAX_ANCHOR_BYTES:
                    raise ValueError(f"anchor exceeds {MAX_ANCHOR_BYTES} bytes: {source}")
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, target)
        target.chmod(0o600)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def load_png_rgba(path: Path) -> tuple[int, int, bytes]:
    if path.stat().st_size > MAX_ANCHOR_BYTES:
        raise ValueError(f"visual PNG exceeds {MAX_ANCHOR_BYTES} bytes: {path}")
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(f"pixel comparison requires PNG screenshots: {path}")
    offset = 8
    width = height = bit_depth = color_type = interlace = None
    seen_ihdr = False
    compressed = bytearray()
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        chunk_data = data[offset + 8:offset + 8 + length]
        crc_end = offset + 12 + length
        if crc_end > len(data):
            raise ValueError(f"truncated PNG chunk: {path}")
        expected_crc = struct.unpack(">I", data[offset + 8 + length:crc_end])[0]
        if zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF != expected_crc:
            raise ValueError(f"PNG CRC mismatch: {path}")
        if chunk_type == b"IHDR":
            if seen_ihdr or len(chunk_data) != 13:
                raise ValueError(f"PNG requires exactly one 13-byte IHDR chunk: {path}")
            seen_ihdr = True
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", chunk_data)
        elif chunk_type == b"IDAT":
            compressed.extend(chunk_data)
        elif chunk_type == b"IEND":
            break
        offset = crc_end
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type)
    if not width or not height or bit_depth != 8 or channels is None or interlace != 0:
        raise ValueError(f"pixel comparison requires non-interlaced 8-bit RGB/RGBA/gray PNG: {path}")
    if width * height > MAX_VISUAL_PIXELS:
        raise ValueError(f"visual PNG exceeds {MAX_VISUAL_PIXELS} pixels: {path}")
    expected_size = height * (width * channels + 1)
    try:
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(bytes(compressed), expected_size + 1)
        remaining = expected_size + 1 - len(raw)
        if remaining > 0:
            raw += decompressor.flush(remaining)
    except zlib.error as exc:
        raise ValueError(f"invalid PNG image data: {path}") from exc
    stride = width * channels
    if len(raw) != expected_size or decompressor.unconsumed_tail or not decompressor.eof:
        raise ValueError(f"PNG scanline size mismatch: {path}")
    rows: list[bytearray] = []
    cursor = 0
    prior = bytearray(stride)
    for _ in range(height):
        filter_type = raw[cursor]
        cursor += 1
        scan = bytearray(raw[cursor:cursor + stride])
        cursor += stride
        for index in range(stride):
            left = scan[index - channels] if index >= channels else 0
            up = prior[index]
            upper_left = prior[index - channels] if index >= channels else 0
            if filter_type == 1:
                scan[index] = (scan[index] + left) & 0xFF
            elif filter_type == 2:
                scan[index] = (scan[index] + up) & 0xFF
            elif filter_type == 3:
                scan[index] = (scan[index] + ((left + up) // 2)) & 0xFF
            elif filter_type == 4:
                estimate = left + up - upper_left
                distances = (abs(estimate - left), abs(estimate - up), abs(estimate - upper_left))
                predictor = (left, up, upper_left)[distances.index(min(distances))]
                scan[index] = (scan[index] + predictor) & 0xFF
            elif filter_type != 0:
                raise ValueError(f"unsupported PNG filter: {filter_type}")
        rows.append(scan)
        prior = scan
    rgba = bytearray()
    for row in rows:
        for index in range(0, len(row), channels):
            pixel = row[index:index + channels]
            if color_type == 6:
                rgba.extend(pixel)
            elif color_type == 2:
                rgba.extend((*pixel, 255))
            elif color_type == 4:
                rgba.extend((pixel[0], pixel[0], pixel[0], pixel[1]))
            else:
                rgba.extend((pixel[0], pixel[0], pixel[0], 255))
    return width, height, bytes(rgba)


def computed_visual_metrics(anchors: list[tuple[str | None, Path]]) -> tuple[float, int]:
    by_role = {role: path for role, path in anchors if role is not None}
    prototype_width, prototype_height, prototype = load_png_rgba(by_role["prototype_screenshot"])
    implementation_width, implementation_height, implementation = load_png_rgba(by_role["implementation_screenshot"])
    diff_width, diff_height, diff = load_png_rgba(by_role["visual_diff"])
    if (diff_width, diff_height) != (implementation_width, implementation_height):
        raise ValueError("visual_diff dimensions must match the implementation screenshot")
    if any(diff[index:index + 3] != b"\x00\x00\x00" for index in range(0, len(diff), 4)):
        raise ValueError("visual_diff must contain zero RGB difference pixels")
    geometry = max(abs(prototype_width - implementation_width), abs(prototype_height - implementation_height))
    if geometry:
        return 1.0, geometry
    pixel_count = prototype_width * prototype_height
    different = sum(prototype[index:index + 4] != implementation[index:index + 4] for index in range(0, len(prototype), 4))
    return different / pixel_count, 0


def load_runtime_trace(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"runtime_trace anchor must be valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"runtime_trace anchor must contain a JSON object: {path}")
    return value


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
    if sys.platform == "win32":
        return set()
    completed = subprocess.run(["ps", "-e", "-o", "pid=", "-o", "ppid="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
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


def run_bounded(
    argv: list[str], cwd: Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, *,
    environment: dict[str, str] | None = None,
    max_capture_bytes: int = MAX_CAPTURE_BYTES,
    input_text: str | None = None,
    allow_process_tree: bool = False,
    deny_process_fork: bool = False,
    writable_roots: list[Path] | None = None,
    read_protected: list[Path] | None = None,
    allowed_unix_sockets: list[Path] | None = None,
    allow_outbound_process_tree: bool = False,
    isolated_codex_home: Path | None = None,
) -> dict[str, Any]:
    if type(max_capture_bytes) is not int or max_capture_bytes < 1:
        raise ValueError("max_capture_bytes must be a positive integer")
    child_environment = dict(os.environ if environment is None else environment)
    for name in ("CODEX_HOME", "DLV_CONVERGENCE_PRIVATE_KEY"):
        child_environment.pop(name, None)
    if isolated_codex_home is not None:
        isolated = isolated_codex_home.resolve()
        writable = [path.resolve() for path in (writable_roots or [])]
        if not isolated.is_dir() or not any(isolated.is_relative_to(path) for path in writable):
            raise ValueError("isolated Codex home must be inside an explicit writable root")
        child_environment["CODEX_HOME"] = str(isolated)
    encoded_input = input_text.encode("utf-8") if input_text is not None else None
    if encoded_input is not None and len(encoded_input) > MAX_CAPTURE_BYTES:
        raise ValueError("bounded command input exceeds the resource contract")
    options: dict[str, Any] = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {"start_new_session": True}
    if sys.platform == "darwin" and (allow_process_tree or allow_outbound_process_tree):
        if resource is None:
            raise ValueError("macOS process-tree sandbox requires Unix resource limits")
        cpu_limit = max(1, timeout_seconds + 1)

        def bound_cpu() -> None:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))

        options["preexec_fn"] = bound_cpu
    process = subprocess.Popen(
        sandboxed_argv(
            argv, cwd, allow_process_tree=allow_process_tree,
            deny_process_fork=deny_process_fork,
            writable_roots=writable_roots, read_protected=read_protected,
            allowed_unix_sockets=allowed_unix_sockets,
            allow_outbound_process_tree=allow_outbound_process_tree,
        ), cwd=cwd, env=child_environment,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options,
    )
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}

    def drain(name: str, stream: Any) -> None:
        try:
            while chunk := stream.read(8192):
                remaining = max_capture_bytes - len(captured[name])
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

    threads = [threading.Thread(target=drain, args=(name, stream), daemon=True) for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for thread in threads:
        thread.start()
    input_thread: threading.Thread | None = None
    if encoded_input is not None:
        assert process.stdin is not None

        def feed_input() -> None:
            try:
                process.stdin.write(encoded_input)
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    pass

        input_thread = threading.Thread(target=feed_input, daemon=True)
        input_thread.start()
    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        descendants = descendant_pids(process.pid)
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            try:
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
    if sys.platform != "win32":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for thread in threads:
        thread.join(timeout=2)
    if input_thread is not None:
        input_thread.join(timeout=2)
    output: dict[str, Any] = {"exit_code": 124 if timed_out else exit_code, "timed_out": timed_out}
    for name in ("stdout", "stderr"):
        text = captured[name].decode("utf-8", errors="replace")
        if truncated[name]:
            text += f"\n[TRUNCATED at {max_capture_bytes} bytes]"
        output[name] = redact_text(text)
    if timed_out:
        output["stderr"] += f"\n[TIMED OUT after {timeout_seconds} seconds]"
    return output
