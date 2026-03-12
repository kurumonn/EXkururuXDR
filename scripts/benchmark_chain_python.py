#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
import sys

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from exkururuxdr.correlation import _cross_product_chain_correlate, event_from_dict


def parse_input(path: Path) -> tuple[int, int, list[dict]]:
    loops = 0
    window_sec = 300
    rows: list[dict] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split("|")
        if parts[0] == "CONFIG":
            if len(parts) != 3:
                raise ValueError(f"invalid CONFIG line {line_no}")
            loops = int(parts[1])
            window_sec = int(parts[2])
        elif parts[0] == "EVENT":
            if len(parts) != 9:
                raise ValueError(f"invalid EVENT line {line_no}")
            labels = [v for v in parts[8].split(",") if v] if parts[8] else []
            rows.append(
                {
                    "event_id": parts[1],
                    "time": parts[2],
                    "product": parts[3],
                    "event_type": parts[4],
                    "src_ip": parts[5],
                    "dst_ip": parts[6],
                    "score": float(parts[7]),
                    "labels": labels,
                }
            )
        else:
            raise ValueError(f"unknown record type line {line_no}")
    if loops < 1:
        raise ValueError("invalid loops")
    return loops, window_sec, rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=Path)
    args = parser.parse_args()
    loops, window_sec, raw_events = parse_input(args.input_file)
    events = [event_from_dict(item) for item in raw_events]

    started = time.perf_counter()
    total_incidents = 0
    for _ in range(loops):
        total_incidents += len(_cross_product_chain_correlate(raw_events, events, window_sec=window_sec))
    elapsed_sec = time.perf_counter() - started
    loops_per_sec = loops / elapsed_sec if elapsed_sec > 0 else 0.0
    print(
        json.dumps(
            {
                "loops": loops,
                "window_sec": window_sec,
                "event_count": len(raw_events),
                "total_incidents": total_incidents,
                "elapsed_sec": elapsed_sec,
                "loops_per_sec": loops_per_sec,
            }
        )
    )


if __name__ == "__main__":
    main()
