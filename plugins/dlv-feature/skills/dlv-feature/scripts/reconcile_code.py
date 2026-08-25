#!/usr/bin/env python3
"""Reconcile declared Graph risk, formal commits, and observed Symbol code risk."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from delivery_graph import compile_graph, formal_feature_commits, graph_risk_vector, load_graph, observed_code_risk_vector


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).expanduser().resolve()
        state = compile_graph(root, args.feature_id)
        graph = load_graph(root, args.feature_id)
        print(json.dumps({
            "declared_design_risk": graph_risk_vector(graph),
            "observed_code_risk": observed_code_risk_vector(root, graph),
            "effective_risk": state["risk"]["effective"],
            "formal_feature_commits": formal_feature_commits(root, args.feature_id),
            "code_status": state["code"]["status"],
        }, ensure_ascii=False, indent=2, sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
