from __future__ import annotations

from typing import Any

ADAPTER_VERSION = "ipros-adapter-v1"

SEVERITY_TO_SCORE = {
    "low": 25,
    "medium": 55,
    "high": 80,
    "critical": 95,
}

ALLOWED_CATEGORIES = {"network", "process", "file", "persistence", "identity", "correlation"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


def adapt_ipros_event(raw: dict[str, Any]) -> dict[str, Any]:
    event_id = str(raw.get("event_id") or raw.get("id") or "").strip()
    if not event_id:
        raise ValueError("ipros_event_id_required")

    time_value = str(raw.get("time") or raw.get("timestamp") or "").strip()
    if not time_value:
        raise ValueError("ipros_time_required")

    category = str(raw.get("category") or "network").strip().lower()
    if category not in ALLOWED_CATEGORIES:
        category = "network"

    severity = str(raw.get("severity") or "medium").strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        severity = "medium"

    event_type = str(raw.get("event_type") or raw.get("type") or "NDR_EVENT").strip()
    if not event_type:
        event_type = "NDR_EVENT"

    labels_raw = raw.get("labels", [])
    if isinstance(labels_raw, str):
        labels = [item.strip() for item in labels_raw.split(",") if item.strip()]
    elif isinstance(labels_raw, list):
        labels = [str(item).strip() for item in labels_raw if str(item).strip()]
    else:
        labels = []
    if not labels:
        labels = ["ipros", "xdr-export"]

    score_value = raw.get("score")
    if isinstance(score_value, (int, float)):
        score = int(max(0, min(100, score_value)))
    else:
        score = SEVERITY_TO_SCORE.get(severity, 50)

    event: dict[str, Any] = {
        "schema_version": "common_security_event_v1",
        "event_id": event_id,
        "time": time_value,
        "product": "exkururuipros",
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "score": score,
        "labels": labels,
        "src_ip": raw.get("src_ip"),
        "dst_ip": raw.get("dst_ip"),
        "raw_ref": str(raw.get("raw_ref") or f"local://ipros/events/{event_id}"),
    }
    for key in ("host", "user", "process", "parent_process", "incident_ref"):
        value = raw.get(key)
        if value not in (None, ""):
            event[key] = value
    return event
