#!/usr/bin/env python3
"""Initialize a schema-v11 Delivery Graph feature."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from delivery_graph import initialize


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_id")
    parser.add_argument("--root", default=".")
    parser.add_argument("--title")
    args = parser.parse_args(argv)
    try:
        print(initialize(Path(args.root), args.feature_id, args.title))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
