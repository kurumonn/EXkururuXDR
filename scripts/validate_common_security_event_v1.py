#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import json

from exkururuxdr.validation import validate_event


def validate_file(path: Path) -> tuple[bool, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        return False, [f"cannot parse json: {exc}"]
    if not isinstance(data, dict):
        return False, ["root must be json object"]
    errors = validate_event(data)
    return len(errors) == 0, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate common_security_event_v1 payload(s).")
    parser.add_argument("files", nargs="+", help="JSON files to validate")
    args = parser.parse_args()

    has_error = False
    for file_arg in args.files:
        path = Path(file_arg)
        ok, errors = validate_file(path)
        if ok:
            print(f"[OK] {path}")
            continue
        has_error = True
        print(f"[NG] {path}")
        for err in errors:
            print(f"  - {err}")
    return 1 if has_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
