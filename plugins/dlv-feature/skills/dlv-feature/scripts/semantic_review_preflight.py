#!/usr/bin/env python3
"""Fail-fast environment diagnostics for isolated semantic Review bootstrap."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from delivery_governance import read_bounded_regular
from delivery_proof import value_digest
from graph_review import semantic_codex_executable, trusted_codex_bootstrap_snapshot


MAX_PLUGIN_FILES = 512
MAX_PLUGIN_FILE_BYTES = 8 * 1024 * 1024


def plugin_tree_digest(plugin_root: Path) -> str:
    records: list[dict[str, object]] = []
    for path in sorted(plugin_root.rglob("*")):
        relative = path.relative_to(plugin_root)
        if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise ValueError(f"plugin payload contains a symlink: {relative.as_posix()}")
        if path.is_dir():
            continue
        if len(records) >= MAX_PLUGIN_FILES:
            raise ValueError("plugin payload exceeds the release file-count bound")
        content = read_bounded_regular(path, MAX_PLUGIN_FILE_BYTES, f"plugin file {relative.as_posix()}")
        assert content is not None
        records.append({
            "path": relative.as_posix(),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    if not records:
        raise ValueError("plugin payload is empty")
    return value_digest(records)


def preflight_payload(*, plugin_root: Path | None = None) -> dict[str, object]:
    plugin_root = plugin_root or Path(__file__).resolve().parents[3]
    manifest_bytes = read_bounded_regular(
        plugin_root / ".codex-plugin/plugin.json", MAX_PLUGIN_FILE_BYTES, "plugin manifest",
    )
    assert manifest_bytes is not None
    manifest = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    actual_version = manifest["version"]
    actual_plugin_sha256 = plugin_tree_digest(plugin_root)
    _, _, modes = trusted_codex_bootstrap_snapshot()
    executable = semantic_codex_executable()
    files = {
        name: {"kind": "regular", "mode": format(mode, "04o")}
        for name, mode in modes.items()
    }
    alignment_bytes = read_bounded_regular(
        plugin_root / "skills/dlv-feature/scripts/product_alignment.py",
        MAX_PLUGIN_FILE_BYTES, "Product Alignment implementation",
    )
    assert alignment_bytes is not None
    return {
        "status": "environment_ready",
        "plugin_identity_verified": False,
        "host_verification_required": True,
        "plugin": manifest["name"],
        "diagnostic_version": actual_version,
        "diagnostic_plugin_sha256": actual_plugin_sha256,
        "diagnostic_product_alignment_sha256": hashlib.sha256(alignment_bytes).hexdigest(),
        "codex_executable": Path(executable).name,
        "bootstrap_files": files,
    }


def main() -> int:
    try:
        payload = preflight_payload()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 1
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
