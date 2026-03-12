from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_events(paths: list[str]) -> list[dict[str, Any]]:
    all_events: list[dict[str, Any]] = []
    for file_path in paths:
        path = Path(file_path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("events"), list):
            all_events.extend(item for item in raw["events"] if isinstance(item, dict))
            continue
        if isinstance(raw, list):
            all_events.extend(item for item in raw if isinstance(item, dict))
            continue
        if isinstance(raw, dict):
            all_events.append(raw)
            continue
        raise ValueError(f"Unsupported JSON shape: {file_path}")
    return all_events

