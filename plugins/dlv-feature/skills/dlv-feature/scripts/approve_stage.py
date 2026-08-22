#!/usr/bin/env python3
"""Compatibility tombstone for the removed schema-v8 human approval command."""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "error: approve_stage.py was removed in delivery schema v9; "
        "run upgrade_v8_to_v9.py for existing deliveries, then use quality_review.py "
        "product|architecture|code_spec",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
