from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    time: str
    product: str
    event_type: str
    severity: str
    score: float
    src_ip: str = ""
    dst_ip: str = ""
    category: str = "correlation"


@dataclass(frozen=True)
class IncidentAggregate:
    incident_key: str
    event_type: str
    src_ip: str
    severity: str
    count: int
    first_seen: str
    last_seen: str
    avg_score: float


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    name: str
    version: str = "1.0.0"
    enabled: bool = True
    description: str = ""
    event_types: tuple[str, ...] = field(default_factory=tuple)
    products: tuple[str, ...] = field(default_factory=tuple)
    categories: tuple[str, ...] = field(default_factory=tuple)
    labels_contains: tuple[str, ...] = field(default_factory=tuple)
    group_by: tuple[str, ...] = ("src_ip",)
    window_sec: int = 300
    min_hits: int = 20
    min_distinct_products: int = 1
    severity: str = "medium"
