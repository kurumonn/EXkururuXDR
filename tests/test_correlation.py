from exkururuxdr.correlation import correlate_events
from exkururuxdr.rules import load_rules


def test_legacy_correlate_events_creates_incident_when_threshold_reached() -> None:
    base = {
        "product": "exkururuipros",
        "event_type": "SCAN-003",
        "severity": "high",
        "score": 90,
        "src_ip": "203.0.113.10",
    }
    events = []
    for i in range(20):
        item = dict(base)
        item["event_id"] = f"evt-{i}"
        item["time"] = f"2026-03-11T10:{i:02d}:00Z"
        events.append(item)

    incidents = correlate_events(events, window_sec=3600, min_hits=20)

    assert len(incidents) == 1
    assert incidents[0]["count"] == 20
    assert incidents[0]["event_type"] == "SCAN-003"


def test_legacy_correlate_events_does_not_create_incident_under_threshold() -> None:
    events = [
        {
            "event_id": f"evt-{i}",
            "time": f"2026-03-11T10:{i:02d}:00Z",
            "product": "exkururuedr",
            "event_type": "SUSPICIOUS_PROCESS",
            "severity": "medium",
            "score": 50,
            "src_ip": "192.0.2.10",
        }
        for i in range(5)
    ]
    incidents = correlate_events(events, window_sec=600, min_hits=6)
    assert incidents == []


def test_rule_based_correlation_creates_cross_product_incident(tmp_path) -> None:
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text(
        """
rules:
  - rule_id: cross-product
    name: Cross product persistence
    enabled: true
    version: 1.0.0
    event_types: [BEACONING, PERSISTENCE_REGISTRY_RUNKEY]
    products: [exkururuipros, exkururuedr]
    group_by: [src_ip]
    window_sec: 300
    min_hits: 2
    min_distinct_products: 2
    severity: high
""".strip(),
        encoding="utf-8",
    )

    events = [
        {
            "event_id": "evt-ndr-1",
            "time": "2026-03-11T10:00:00Z",
            "product": "exkururuipros",
            "category": "network",
            "event_type": "BEACONING",
            "severity": "medium",
            "score": 70,
            "src_ip": "192.0.2.10",
            "labels": ["beacon"],
        },
        {
            "event_id": "evt-edr-1",
            "time": "2026-03-11T10:03:00Z",
            "product": "exkururuedr",
            "category": "persistence",
            "event_type": "PERSISTENCE_REGISTRY_RUNKEY",
            "severity": "high",
            "score": 92,
            "src_ip": "192.0.2.10",
            "labels": ["registry-runkey"],
        },
    ]

    incidents = correlate_events(events, rules=load_rules(rules_file))

    assert len(incidents) == 1
    assert incidents[0]["rule_id"] == "cross-product"
    assert incidents[0]["product_count"] == 2
    assert incidents[0]["group"]["src_ip"] == "192.0.2.10"


def test_rule_loader_skips_disabled_rule(tmp_path) -> None:
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text(
        """
rules:
  - rule_id: disabled-rule
    name: Disabled rule
    enabled: false
    event_types: [SUSPICIOUS_PROCESS]
    group_by: [src_ip]
    window_sec: 300
    min_hits: 1
    severity: low
""".strip(),
        encoding="utf-8",
    )
    events = [
        {
            "event_id": "evt-1",
            "time": "2026-03-11T10:00:00Z",
            "product": "exkururuedr",
            "category": "process",
            "event_type": "SUSPICIOUS_PROCESS",
            "severity": "medium",
            "score": 60,
            "src_ip": "198.51.100.20",
            "labels": ["powershell"],
        }
    ]
    incidents = correlate_events(events, rules=load_rules(rules_file))
    assert incidents == []
