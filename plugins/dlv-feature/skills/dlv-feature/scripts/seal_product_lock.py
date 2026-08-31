#!/usr/bin/env python3
"""Seal a SAFE schema-v13 Product Alignment as an immutable Product Lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from delivery_graph import compile_graph, confined_project_path, feature_dir, graph_path, load_graph, prototype_errors, render_stage_document, stage_hash
from delivery_governance import load_source_revision
from delivery_governance import load_ledger
from delivery_proof import exclusive_file_lock, file_digest
from product_lock import delivery_prototype_digest, load_alignment, lock_digest, validate_alignment_record


def _open_directory_chain(root: Path, parts: tuple[str, ...], *, create_final: bool = False) -> int:
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, name in enumerate(parts):
            if create_final and index == len(parts) - 1:
                try:
                    os.mkdir(name, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _directory_chain_matches(root: Path, parts: tuple[str, ...], pinned_fd: int) -> bool:
    try:
        current_fd = _open_directory_chain(root, parts)
    except OSError:
        return False
    try:
        pinned, current = os.fstat(pinned_fd), os.fstat(current_fd)
        return (pinned.st_dev, pinned.st_ino) == (current.st_dev, current.st_ino)
    finally:
        os.close(current_fd)


def _read_regular_at(directory_fd: int, name: str, limit: int = 8 * 1024 * 1024) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
            raise ValueError("Product Lock artifact is not a bounded single-linked regular file")
        content = b""
        while chunk := os.read(descriptor, limit + 1 - len(content)):
            content += chunk
            if len(content) > limit:
                raise ValueError("Product Lock artifact exceeds size limit")
        return content
    finally:
        os.close(descriptor)


def _write_exclusive_at(directory_fd: int, name: str, content: bytes) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Product Lock artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_optional_text_at(directory_fd: int, name: str, limit: int = 64 * 1024 * 1024) -> str | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
            raise ValueError("generated artifact is not a bounded single-linked regular file")
        content = b""
        while chunk := os.read(descriptor, limit + 1 - len(content)):
            content += chunk
            if len(content) > limit:
                raise ValueError("generated artifact exceeds rollback size limit")
        return content.decode("utf-8")
    finally:
        os.close(descriptor)


def _replace_text_at(directory_fd: int, name: str, content: str) -> None:
    temporary = f".{name}.rollback-{secrets.token_hex(8)}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(content.encode("utf-8"))
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("generated artifact rollback made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)
    os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def _restore_at_if_unchanged(
    directory_fd: int, name: str, original: str | None, transaction_value: str | None,
) -> bool:
    if _read_optional_text_at(directory_fd, name) != transaction_value:
        return False
    if original is None:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.fsync(directory_fd)
    else:
        _replace_text_at(directory_fd, name, original)
    return True


def seal(root: Path, feature_id: str, alignment_path: Path) -> Path:
    root = root.expanduser().resolve()
    directory = feature_dir(root, feature_id)
    alignment_path = alignment_path.expanduser().absolute()
    alignment_directory = confined_project_path(
        root, Path(".dlv") / "product-alignments" / feature_id, "Product Alignment directory",
    )
    try:
        alignment_path.relative_to(alignment_directory)
    except ValueError as exc:
        raise ValueError("Product Lock accepts only a content-addressed Product Alignment artifact") from exc
    if not alignment_path.is_file() or alignment_path.resolve() != alignment_path.absolute():
        raise ValueError("Product Alignment artifact is missing or symlinked")
    graph = load_graph(root, feature_id)
    provenance_errors = prototype_errors(root, feature_id, graph)
    if provenance_errors:
        raise ValueError("Product Lock requires a current Delivery Prototype: " + "; ".join(provenance_errors))
    source = load_source_revision(directory, feature_id, graph["source_revision"])
    alignment = load_alignment(alignment_path)
    alignment_sha256 = file_digest(alignment_path)
    prd_path = directory / "prd.md"
    expected_prd = render_stage_document(graph, "product")
    if not prd_path.is_file() or prd_path.read_text(encoding="utf-8") != expected_prd:
        raise ValueError("compile the current Product Graph before sealing Product Lock")
    required = {
        "feature_id": feature_id,
        "source_revision": graph["source_revision"],
        "source_digest": source["source_digest"],
        "product_subgraph_sha256": stage_hash(graph, "product"),
        "prd_sha256": file_digest(prd_path),
        "delivery_prototype_sha256": delivery_prototype_digest(graph),
    }
    for key, value in required.items():
        if alignment.get(key) != value:
            raise ValueError(f"Product Alignment {key} is stale")
    alignment_errors = validate_alignment_record(
        alignment, graph, source, required["product_subgraph_sha256"], required["prd_sha256"],
        directory=directory,
    )
    if alignment_errors or alignment.get("verdict") != "SAFE":
        raise ValueError("Product Lock requires an authentic SAFE Product Alignment: " + "; ".join(alignment_errors))
    expected_alignment_name = f"ALN-{alignment['alignment_digest'][:12]}.json"
    if alignment_path.name != expected_alignment_name or alignment_path.parent != alignment_directory:
        raise ValueError("Product Alignment artifact name disagrees with its content digest")
    decisions = source.get("decisions", [])
    record = {
        "schema_version": 13,
        **required,
        "alignment_digest": alignment["alignment_digest"],
        "alignment_verdict": alignment["verdict"],
        "source_coverage": alignment["source_coverage"],
        "owner_decision_refs": sorted(item["id"] for item in decisions),
    }
    record["lock_digest"] = lock_digest(record)
    lock_id = f"PCL-{record['lock_digest'][:12]}"
    destination = confined_project_path(
        root, directory.relative_to(root) / "product-locks" / f"{lock_id}.json", "Product Lock artifact",
    )
    lock = confined_project_path(root, Path(".dlv") / "runs" / feature_id / ".feature.lock", "feature lock")
    with exclusive_file_lock(lock):
        if not alignment_path.is_file() or file_digest(alignment_path) != alignment_sha256:
            raise ValueError("Product Alignment changed while Product Lock was sealing")
        current = load_graph(root, feature_id)
        if stage_hash(current, "product") != required["product_subgraph_sha256"] or current["source_revision"] != required["source_revision"]:
            raise ValueError("Product Graph changed while Product Lock was sealing")
        current_source = load_source_revision(directory, feature_id, current["source_revision"])
        if current_source["source_digest"] != required["source_digest"]:
            raise ValueError("Source Revision changed while Product Lock was sealing")
        current_prototype_errors = prototype_errors(root, feature_id, current)
        if current_prototype_errors:
            raise ValueError("Delivery Prototype changed while Product Lock was sealing: " + "; ".join(current_prototype_errors))
        if (
            not prd_path.is_file() or prd_path.resolve() != prd_path.absolute()
            or prd_path.read_text(encoding="utf-8") != expected_prd
            or file_digest(prd_path) != required["prd_sha256"]
        ):
            raise ValueError("PRD changed while Product Lock was sealing")
        first_lock = current.get("product_lock") is None
        ledger = load_ledger(root, feature_id)
        if first_lock and ledger.get("campaigns"):
            raise ValueError("cannot establish the first Product Lock after architecture Review campaigns")
        product_parts = (*directory.relative_to(root).parts, "product-locks")
        product_fd = _open_directory_chain(root, product_parts, create_final=True)
        content = json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        content_bytes = content.encode("utf-8")
        created_destination = False
        try:
            try:
                existing = _read_regular_at(product_fd, destination.name)
            except FileNotFoundError:
                _write_exclusive_at(product_fd, destination.name, content_bytes)
                created_destination = True
            else:
                if existing != content_bytes:
                    raise ValueError("content-addressed Product Lock collision")
            os.fsync(product_fd)
            if not _directory_chain_matches(root, product_parts, product_fd):
                raise ValueError("Product Lock directory changed during artifact commit")

            feature_parts = directory.relative_to(root).parts
            findings_parts = (".dlv", "findings", feature_id)
            feature_fd = _open_directory_chain(root, feature_parts)
            findings_fd = _open_directory_chain(root, findings_parts)
            try:
                graph_file = graph_path(root, feature_id)
                ledger_file = root / ".dlv" / "findings" / feature_id / "ledger.json"
                generated = [
                    (feature_fd, "delivery-graph.json", graph_file),
                    (findings_fd, "ledger.json", ledger_file),
                    *[
                        (feature_fd, name, directory / name)
                        for name in ("prd.md", "architecture-design.md", "code-spec.md", "proof-contract.json", "state.json")
                    ],
                ]
                originals = {(fd, name): _read_optional_text_at(fd, name) for fd, name, _ in generated}
                transaction_values = dict(originals)
                current["product_lock"] = {"id": lock_id, "sha256": hashlib.sha256(content_bytes).hexdigest()}
                expected_graph = json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
                try:
                    _replace_text_at(feature_fd, "delivery-graph.json", expected_graph)
                    transaction_values[(feature_fd, "delivery-graph.json")] = expected_graph
                    if first_lock:
                        ledger["convergence_events"] = []
                        ledger_content = json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
                        _replace_text_at(findings_fd, "ledger.json", ledger_content)
                        transaction_values[(findings_fd, "ledger.json")] = ledger_content
                    compiled_outputs: dict[Path, str] = {}
                    state = compile_graph(root, feature_id, _lock_held=True, _captured_outputs=compiled_outputs)
                    for fd, name, path in generated:
                        if path in compiled_outputs:
                            transaction_values[(fd, name)] = compiled_outputs[path]
                    post_compile_source = load_source_revision(directory, feature_id, current["source_revision"])
                    if (
                        state.get("readiness", {}).get("product_lock_blocked")
                        or post_compile_source["source_digest"] != required["source_digest"]
                        or not _directory_chain_matches(root, product_parts, product_fd)
                    ):
                        raise ValueError("Product inputs changed while Product Lock was compiling")
                except BaseException as exc:
                    preserved = [
                        path for fd, name, path in reversed(generated)
                        if not _restore_at_if_unchanged(
                            fd, name, originals[(fd, name)], transaction_values[(fd, name)],
                        )
                    ]
                    if preserved:
                        raise ValueError(
                            "Product Lock sealing failed; concurrent generated-artifact edits were preserved: "
                            + ", ".join(path.name for path in preserved)
                        ) from exc
                    raise
            finally:
                os.close(findings_fd)
                os.close(feature_fd)
        except BaseException:
            if created_destination:
                try:
                    if _read_regular_at(product_fd, destination.name) == content_bytes:
                        os.unlink(destination.name, dir_fd=product_fd)
                        os.fsync(product_fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(product_fd)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--alignment", required=True)
    args = parser.parse_args(argv)
    try:
        print(seal(Path(args.root), args.feature_id, Path(args.alignment)))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
