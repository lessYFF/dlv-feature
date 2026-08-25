#!/usr/bin/env python3
"""Bounded command and runtime-evidence helpers for schema-v10 verification."""

from __future__ import annotations

import json
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import zlib
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 300
MAX_CAPTURE_BYTES = 1_048_576
MAX_ANCHOR_BYTES = 10_485_760
MAX_VISUAL_PIXELS = 16_777_216


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


def run_bounded(argv: list[str], cwd: Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    options: dict[str, Any] = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {"start_new_session": True}
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
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

    threads = [threading.Thread(target=drain, args=(name, stream), daemon=True) for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for thread in threads:
        thread.start()
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
    for thread in threads:
        thread.join(timeout=2)
    output: dict[str, Any] = {"exit_code": 124 if timed_out else exit_code, "timed_out": timed_out}
    for name in ("stdout", "stderr"):
        text = captured[name].decode("utf-8", errors="replace")
        if truncated[name]:
            text += f"\n[TRUNCATED at {MAX_CAPTURE_BYTES} bytes]"
        output[name] = redact_text(text)
    if timed_out:
        output["stderr"] += f"\n[TIMED OUT after {timeout_seconds} seconds]"
    return output
