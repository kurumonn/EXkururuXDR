from __future__ import annotations

import ipaddress
from datetime import datetime
from functools import lru_cache
from typing import Any


ALLOWED_PRODUCTS = {"exkururuipros", "exkururuedr", "exkururuxdr_import"}
ALLOWED_CATEGORIES = {"network", "process", "file", "persistence", "identity", "correlation"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
REQUIRED_FIELDS = (
    "category",
    "event_id",
    "event_type",
    "labels",
    "product",
    "schema_version",
    "score",
    "severity",
    "time",
)
ALLOWED_PRODUCTS_MSG = str(sorted(ALLOWED_PRODUCTS))
ALLOWED_CATEGORIES_MSG = str(sorted(ALLOWED_CATEGORIES))
ALLOWED_SEVERITIES_MSG = str(sorted(ALLOWED_SEVERITIES))
_STATIC_FIELDS = ("schema_version", "product", "category", "event_type", "severity", "labels")
_REQUIRED_STATIC_FIELDS = ("schema_version", "product", "category", "event_type", "severity", "labels")
_REQUIRED_DYNAMIC_FIELDS = ("event_id", "time", "score")
_MISSING = object()


@lru_cache(maxsize=4096)
def _parse_iso8601_cached(value: str) -> bool:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def parse_iso8601(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    return _parse_iso8601_cached(value)


@lru_cache(maxsize=4096)
def _is_ip_string(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_ip_or_none(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, str) or not value:
        return False
    return _is_ip_string(value)


def _validate_static_fields(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = [field for field in _REQUIRED_STATIC_FIELDS if field not in payload]
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")

    schema_version = payload.get("schema_version")
    product = payload.get("product")
    category = payload.get("category")
    event_type = payload.get("event_type")
    severity = payload.get("severity")
    labels = payload.get("labels")

    if schema_version != "common_security_event_v1":
        errors.append("schema_version must be common_security_event_v1")
    if product not in ALLOWED_PRODUCTS:
        errors.append(f"product must be one of {ALLOWED_PRODUCTS_MSG}")
    if category not in ALLOWED_CATEGORIES:
        errors.append(f"category must be one of {ALLOWED_CATEGORIES_MSG}")
    if not isinstance(event_type, str) or not event_type:
        errors.append("event_type must be non-empty string")
    if severity not in ALLOWED_SEVERITIES:
        errors.append(f"severity must be one of {ALLOWED_SEVERITIES_MSG}")
    if not isinstance(labels, list):
        errors.append("labels must be array")
    elif not all(isinstance(x, str) for x in labels):
        errors.append("labels must contain only strings")
    return errors


def _validate_dynamic_fields(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = [field for field in _REQUIRED_DYNAMIC_FIELDS if field not in payload]
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")

    event_id = payload.get("event_id")
    event_time = payload.get("time")
    score = payload.get("score")
    src_ip = payload.get("src_ip")
    dst_ip = payload.get("dst_ip")

    if not isinstance(event_id, str) or not event_id:
        errors.append("event_id must be non-empty string")
    if not parse_iso8601(event_time):
        errors.append("time must be ISO8601 date-time")

    if not isinstance(score, (int, float)):
        errors.append("score must be number")
    elif score < 0 or score > 100:
        errors.append("score must be in range 0..100")

    if not _is_ip_or_none(src_ip):
        errors.append("src_ip must be valid IP string or null")
    if not _is_ip_or_none(dst_ip):
        errors.append("dst_ip must be valid IP string or null")

    return errors


def validate_event(payload: dict[str, Any]) -> list[str]:
    return _validate_static_fields(payload) + _validate_dynamic_fields(payload)


def validate_event_batch(payloads: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    valid_events: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if not payloads:
        return valid_events, errors

    all_same_static = True
    static_values: dict[str, Any] = {}
    first = payloads[0]
    if not isinstance(first, dict):
        all_same_static = False
    else:
        for field in _STATIC_FIELDS:
            static_values[field] = first.get(field, _MISSING)
        for item in payloads[1:]:
            if not isinstance(item, dict):
                all_same_static = False
                break
            for field in _STATIC_FIELDS:
                if item.get(field, _MISSING) != static_values[field]:
                    all_same_static = False
                    break
            if not all_same_static:
                break

    static_errors: list[str] = []
    if all_same_static:
        static_probe = {k: v for k, v in static_values.items() if v is not _MISSING}
        static_errors = _validate_static_fields(static_probe)

    for idx, event in enumerate(payloads):
        if not isinstance(event, dict):
            errors.append({"index": idx, "event_id": "", "errors": ["event must be object"]})
            continue
        if all_same_static:
            event_errors = static_errors + _validate_dynamic_fields(event)
        else:
            event_errors = validate_event(event)
        if event_errors:
            errors.append({"index": idx, "event_id": event.get("event_id", ""), "errors": event_errors})
            continue
        valid_events.append(event)
    return valid_events, errors
