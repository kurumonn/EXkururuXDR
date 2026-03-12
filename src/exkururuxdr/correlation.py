from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import CorrelationRule, IncidentAggregate, SecurityEvent


def parse_iso8601(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def event_from_dict(raw: dict[str, Any]) -> SecurityEvent:
    return SecurityEvent(
        event_id=str(raw.get("event_id", "")),
        time=str(raw.get("time", "")),
        product=str(raw.get("product", "")),
        event_type=str(raw.get("event_type", "")),
        severity=str(raw.get("severity", "low")),
        score=float(raw.get("score", 0.0)),
        src_ip=str(raw.get("src_ip", "")),
        dst_ip=str(raw.get("dst_ip", "")),
        category=str(raw.get("category", "correlation")),
    )


def correlate_events(
    raw_events: list[dict[str, Any]],
    window_sec: int = 300,
    min_hits: int = 20,
    rules: list[CorrelationRule] | None = None,
) -> list[dict[str, Any]]:
    events = [event_from_dict(item) for item in raw_events]
    if rules:
        incidents: list[dict[str, Any]] = []
        for rule in rules:
            if not rule.enabled:
                continue
            incidents.extend(_correlate_with_rule(raw_events, events, rule))
        return incidents

    return _legacy_correlate(events, window_sec=window_sec, min_hits=min_hits)


def _legacy_correlate(events: list[SecurityEvent], *, window_sec: int, min_hits: int) -> list[dict[str, Any]]:
    ts_cache: dict[str, datetime] = {}
    windows: dict[tuple[str, str, str], list[SecurityEvent]] = defaultdict(list)
    for ev in events:
        if not ev.time or not ev.event_type:
            continue
        key = (ev.event_type, ev.src_ip or "-", ev.severity)
        windows[key].append(ev)

    aggregates: list[IncidentAggregate] = []
    for (event_type, src_ip, severity), group in windows.items():
        ordered = sorted(((_cached_ts(item.time, ts_cache), item) for item in group), key=lambda pair: pair[0])
        for bucket in _window_buckets_preparsed(ordered, window_sec):
            if len(bucket) >= min_hits:
                aggregates.append(_to_legacy_incident(event_type, src_ip, severity, bucket))
    return [asdict(item) for item in aggregates]


def _correlate_with_rule(
    raw_events: list[dict[str, Any]],
    events: list[SecurityEvent],
    rule: CorrelationRule,
) -> list[dict[str, Any]]:
    ts_cache: dict[str, datetime] = {}
    indexed = list(zip(raw_events, events))
    filtered = [(raw, ev, _cached_ts(ev.time, ts_cache)) for raw, ev in indexed if _matches_rule(raw, ev, rule)]
    groups: dict[tuple[str, ...], list[tuple[dict[str, Any], SecurityEvent, datetime]]] = defaultdict(list)

    for raw, ev, ts in filtered:
        key = tuple(_group_value(raw, ev, field) for field in rule.group_by)
        groups[key].append((raw, ev, ts))

    incidents: list[dict[str, Any]] = []
    for group_key, group in groups.items():
        sorted_group = sorted(group, key=lambda item: item[2])
        for bucket_pairs in _window_pair_buckets_preparsed(sorted_group, rule.window_sec):
            distinct_products = sorted({ev.product for _, ev, _ in bucket_pairs if ev.product})
            if len(bucket_pairs) < rule.min_hits or len(distinct_products) < rule.min_distinct_products:
                continue
            incidents.append(_to_rule_incident(rule, group_key, bucket_pairs, distinct_products))
    return incidents


def _cached_ts(value: str, cache: dict[str, datetime]) -> datetime:
    ts = cache.get(value)
    if ts is not None:
        return ts
    ts = parse_iso8601(value)
    cache[value] = ts
    return ts


def _window_buckets_preparsed(
    events_with_ts: list[tuple[datetime, SecurityEvent]],
    window_sec: int,
) -> list[list[SecurityEvent]]:
    if not events_with_ts:
        return []
    buckets: list[list[SecurityEvent]] = []
    start = events_with_ts[0][0]
    end = start + timedelta(seconds=window_sec)
    bucket: list[SecurityEvent] = []
    for ts, ev in events_with_ts:
        if ts <= end:
            bucket.append(ev)
            continue
        buckets.append(bucket)
        start = ts
        end = start + timedelta(seconds=window_sec)
        bucket = [ev]
    if bucket:
        buckets.append(bucket)
    return buckets


def _window_pair_buckets_preparsed(
    sorted_pairs: list[tuple[dict[str, Any], SecurityEvent, datetime]],
    window_sec: int,
) -> list[list[tuple[dict[str, Any], SecurityEvent, datetime]]]:
    if not sorted_pairs:
        return []
    buckets: list[list[tuple[dict[str, Any], SecurityEvent, datetime]]] = []
    start = sorted_pairs[0][2]
    end = start + timedelta(seconds=window_sec)
    bucket: list[tuple[dict[str, Any], SecurityEvent, datetime]] = []
    for pair in sorted_pairs:
        ts = pair[2]
        if ts <= end:
            bucket.append(pair)
            continue
        buckets.append(bucket)
        start = ts
        end = start + timedelta(seconds=window_sec)
        bucket = [pair]
    if bucket:
        buckets.append(bucket)
    return buckets


def _window_buckets(events: list[SecurityEvent], window_sec: int) -> list[list[SecurityEvent]]:
    if not events:
        return []
    buckets: list[list[SecurityEvent]] = []
    start = parse_iso8601(events[0].time)
    end = start + timedelta(seconds=window_sec)
    bucket: list[SecurityEvent] = []
    for ev in events:
        ts = parse_iso8601(ev.time)
        if ts <= end:
            bucket.append(ev)
            continue
        buckets.append(bucket)
        start = ts
        end = start + timedelta(seconds=window_sec)
        bucket = [ev]
    if bucket:
        buckets.append(bucket)
    return buckets


def _window_pair_buckets(
    sorted_pairs: list[tuple[dict[str, Any], SecurityEvent]],
    window_sec: int,
) -> list[list[tuple[dict[str, Any], SecurityEvent]]]:
    if not sorted_pairs:
        return []
    buckets: list[list[tuple[dict[str, Any], SecurityEvent]]] = []
    start = parse_iso8601(sorted_pairs[0][1].time)
    end = start + timedelta(seconds=window_sec)
    bucket: list[tuple[dict[str, Any], SecurityEvent]] = []
    for pair in sorted_pairs:
        ts = parse_iso8601(pair[1].time)
        if ts <= end:
            bucket.append(pair)
            continue
        buckets.append(bucket)
        start = ts
        end = start + timedelta(seconds=window_sec)
        bucket = [pair]
    if bucket:
        buckets.append(bucket)
    return buckets


def _matches_rule(raw: dict[str, Any], ev: SecurityEvent, rule: CorrelationRule) -> bool:
    if rule.event_types and ev.event_type not in rule.event_types:
        return False
    if rule.products and ev.product not in rule.products:
        return False
    if rule.categories and ev.category not in rule.categories:
        return False
    if rule.labels_contains:
        labels = raw.get("labels") if isinstance(raw.get("labels"), list) else []
        if not all(label in labels for label in rule.labels_contains):
            return False
    return True


def _group_value(raw: dict[str, Any], ev: SecurityEvent, field: str) -> str:
    if field == "src_ip":
        return ev.src_ip or "-"
    if field == "dst_ip":
        return ev.dst_ip or "-"
    if field == "event_type":
        return ev.event_type or "-"
    if field == "product":
        return ev.product or "-"
    if field == "category":
        return ev.category or "-"
    return str(raw.get(field, "-") or "-")


def _to_legacy_incident(
    event_type: str,
    src_ip: str,
    severity: str,
    events: list[SecurityEvent],
) -> IncidentAggregate:
    first_seen = events[0].time
    last_seen = events[-1].time
    avg_score = sum(ev.score for ev in events) / max(1, len(events))
    incident_key = f"{event_type}:{src_ip}:{first_seen}"
    return IncidentAggregate(
        incident_key=incident_key,
        event_type=event_type,
        src_ip=src_ip,
        severity=severity,
        count=len(events),
        first_seen=first_seen,
        last_seen=last_seen,
        avg_score=round(avg_score, 2),
    )


def _to_rule_incident(
    rule: CorrelationRule,
    group_key: tuple[str, ...],
    bucket_pairs: list[tuple[dict[str, Any], SecurityEvent, datetime]],
    distinct_products: list[str],
) -> dict[str, Any]:
    events = [ev for _, ev, _ in bucket_pairs]
    first_seen = events[0].time
    last_seen = events[-1].time
    avg_score = round(sum(ev.score for ev in events) / max(1, len(events)), 2)
    group = {field: value for field, value in zip(rule.group_by, group_key)}
    return {
        "incident_key": f"{rule.rule_id}:{':'.join(group_key)}:{first_seen}",
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "rule_version": rule.version,
        "severity": rule.severity,
        "status": "open",
        "count": len(events),
        "product_count": len(distinct_products),
        "products": distinct_products,
        "group": group,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "avg_score": avg_score,
        "event_ids": [ev.event_id for ev in events],
        "event_types": sorted({ev.event_type for ev in events if ev.event_type}),
        "src_ips": sorted({ev.src_ip for ev in events if ev.src_ip}),
        "dst_ips": sorted({ev.dst_ip for ev in events if ev.dst_ip}),
    }


def _cross_product_chain_correlate(
    raw_events: list[dict[str, Any]],
    events: list[SecurityEvent],
    *,
    window_sec: int,
) -> list[dict[str, Any]]:
    indexed = [(raw, ev) for raw, ev in zip(raw_events, events) if ev.src_ip]
    groups: dict[str, list[tuple[dict[str, Any], SecurityEvent]]] = defaultdict(list)
    for raw, ev in indexed:
        groups[ev.src_ip].append((raw, ev))

    incidents: list[dict[str, Any]] = []
    for src_ip, pairs in groups.items():
        pairs_sorted = sorted(pairs, key=lambda item: parse_iso8601(item[1].time))
        for bucket_pairs in _window_pair_buckets(pairs_sorted, window_sec):
            ndr_pairs = [item for item in bucket_pairs if _is_ndr_flow_event(item[0], item[1])]
            edr_pairs = [item for item in bucket_pairs if _is_edr_endpoint_event(item[0], item[1])]
            if not ndr_pairs or not edr_pairs:
                continue
            all_pairs = ndr_pairs + edr_pairs
            all_events = [ev for _, ev in all_pairs]
            first_seen = all_events[0].time
            last_seen = all_events[-1].time
            avg_score = round(sum(ev.score for ev in all_events) / max(1, len(all_events)), 2)
            incidents.append(
                {
                    "incident_key": f"xdr-ndr-edr-chain:{src_ip}:{first_seen}",
                    "rule_id": "xdr-ndr-edr-chain",
                    "rule_name": "NDR flow anomaly + EDR endpoint anomaly chain",
                    "rule_version": "1.0.0",
                    "severity": "high",
                    "status": "open",
                    "count": len(all_events),
                    "product_count": len(sorted({ev.product for ev in all_events if ev.product})),
                    "products": sorted({ev.product for ev in all_events if ev.product}),
                    "group": {"src_ip": src_ip},
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "avg_score": avg_score,
                    "event_ids": [ev.event_id for ev in all_events],
                    "event_types": sorted({ev.event_type for ev in all_events if ev.event_type}),
                    "src_ips": [src_ip],
                    "dst_ips": sorted({ev.dst_ip for ev in all_events if ev.dst_ip}),
                    "chain": {
                        "ndr_hits": len(ndr_pairs),
                        "edr_hits": len(edr_pairs),
                    },
                }
            )
    return incidents


def _is_ndr_flow_event(raw: dict[str, Any], ev: SecurityEvent) -> bool:
    if ev.product not in {"exkururuipros", "noujyuku_ndr_sensor"}:
        return False
    event_type = (ev.event_type or "").upper()
    if event_type in {
        "FLOW_EWMA_SPIKE",
        "FLOW_PORT_SCAN",
        "FLOW_FAN_OUT",
        "FLOW_BEACONING",
        "SUSPICIOUS_OUTBOUND",
        "BEACONING",
    }:
        return True
    labels = raw.get("labels") if isinstance(raw.get("labels"), list) else []
    label_set = {str(v).strip().lower() for v in labels}
    return "flow" in label_set or "anomaly" in label_set


def _is_edr_endpoint_event(raw: dict[str, Any], ev: SecurityEvent) -> bool:
    if ev.product != "exkururuedr":
        return False
    event_type = (ev.event_type or "").upper()
    if event_type in {
        "SUSPICIOUS_PROCESS",
        "PERSISTENCE_REGISTRY_RUNKEY",
        "PERSISTENCE_SCHEDULED_TASK",
        "CREDENTIAL_DUMPING",
    }:
        return True
    labels = raw.get("labels") if isinstance(raw.get("labels"), list) else []
    label_set = {str(v).strip().lower() for v in labels}
    return bool({"encoded-command", "powershell", "runkey", "credential-dump"} & label_set)
