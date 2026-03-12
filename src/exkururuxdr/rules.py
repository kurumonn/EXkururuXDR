from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import CorrelationRule


def load_rules(rule_file: str | Path) -> list[CorrelationRule]:
    path = Path(rule_file)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules_raw = raw.get("rules", raw if isinstance(raw, list) else [])
    if not isinstance(rules_raw, list):
        raise ValueError("rules file must contain 'rules' array or be an array")

    rules: list[CorrelationRule] = []
    for item in rules_raw:
        if not isinstance(item, dict):
            raise ValueError("each rule must be an object")
        rules.append(_rule_from_dict(item))
    return rules


def _rule_from_dict(item: dict[str, Any]) -> CorrelationRule:
    rule_id = str(item.get("rule_id", "")).strip()
    name = str(item.get("name", "")).strip()
    if not rule_id or not name:
        raise ValueError("rule_id and name are required")

    return CorrelationRule(
        rule_id=rule_id,
        name=name,
        version=str(item.get("version", "1.0.0")),
        enabled=bool(item.get("enabled", True)),
        description=str(item.get("description", "")),
        event_types=tuple(str(v) for v in item.get("event_types", []) if str(v).strip()),
        products=tuple(str(v) for v in item.get("products", []) if str(v).strip()),
        categories=tuple(str(v) for v in item.get("categories", []) if str(v).strip()),
        labels_contains=tuple(str(v) for v in item.get("labels_contains", []) if str(v).strip()),
        group_by=tuple(str(v) for v in item.get("group_by", ["src_ip"]) if str(v).strip()),
        window_sec=max(1, int(item.get("window_sec", 300))),
        min_hits=max(1, int(item.get("min_hits", 20))),
        min_distinct_products=max(1, int(item.get("min_distinct_products", 1))),
        severity=str(item.get("severity", "medium")),
    )
