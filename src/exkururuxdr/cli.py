from __future__ import annotations

import argparse
import json
import sys

from .correlation import correlate_events
from .io import load_events
from .rules import load_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Correlate common_security_event_v1 events.")
    parser.add_argument("inputs", nargs="+", help="Input JSON file(s)")
    parser.add_argument("--window-sec", type=int, default=300, help="Aggregation window seconds")
    parser.add_argument("--min-hits", type=int, default=20, help="Minimum hits to open incident")
    parser.add_argument("--rules", help="YAML correlation rule file")
    parser.add_argument("--pretty", action="store_true", help="Pretty print output")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    events = load_events(args.inputs)
    rules = load_rules(args.rules) if args.rules else None
    incidents = correlate_events(events, window_sec=args.window_sec, min_hits=args.min_hits, rules=rules)
    if args.pretty:
        json.dump({"incidents": incidents}, sys.stdout, ensure_ascii=False, indent=2)
    else:
        json.dump({"incidents": incidents}, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
