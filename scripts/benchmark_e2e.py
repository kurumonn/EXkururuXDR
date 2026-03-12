#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import random
import statistics
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BenchResult:
    total_events: int
    accepted_events: int
    failed_events: int
    loss_events: int
    ingest_avg_ms: float
    ingest_p50_ms: float
    ingest_p95_ms: float
    ingest_eps: float
    ingest_batch_avg_ms: float
    ingest_batch_p50_ms: float
    ingest_batch_p95_ms: float
    ingest_batch_eps: float
    incident_ms: float
    case_ms: float
    action_ms: float
    dispatch_ms: float
    rss_mb: float
    cpu_sec: float

    def as_dict(self) -> dict[str, float | int]:
        return {
            "total_events": self.total_events,
            "accepted_events": self.accepted_events,
            "failed_events": self.failed_events,
            "loss_events": self.loss_events,
            "ingest_avg_ms": round(self.ingest_avg_ms, 3),
            "ingest_p50_ms": round(self.ingest_p50_ms, 3),
            "ingest_p95_ms": round(self.ingest_p95_ms, 3),
            "ingest_eps": round(self.ingest_eps, 3),
            "ingest_batch_avg_ms": round(self.ingest_batch_avg_ms, 3),
            "ingest_batch_p50_ms": round(self.ingest_batch_p50_ms, 3),
            "ingest_batch_p95_ms": round(self.ingest_batch_p95_ms, 3),
            "ingest_batch_eps": round(self.ingest_batch_eps, 3),
            "incident_ms": round(self.incident_ms, 3),
            "case_ms": round(self.case_ms, 3),
            "action_ms": round(self.action_ms, 3),
            "dispatch_ms": round(self.dispatch_ms, 3),
            "rss_mb": round(self.rss_mb, 3),
            "cpu_sec": round(self.cpu_sec, 3),
        }


def req(method: str, url: str, payload: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    data = None
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url=url, method=method, data=data, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return int(response.getcode()), json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        if not body:
            return int(exc.code), {}
        try:
            return int(exc.code), json.loads(body)
        except json.JSONDecodeError:
            return int(exc.code), {"raw": body}


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    values_sorted = sorted(values)
    k = (len(values_sorted) - 1) * p
    f = int(k)
    c = min(f + 1, len(values_sorted) - 1)
    if f == c:
        return values_sorted[f]
    return values_sorted[f] + (values_sorted[c] - values_sorted[f]) * (k - f)


def read_proc_usage(pid: int | None) -> tuple[float, float]:
    if not pid:
        return 0.0, 0.0
    status = Path(f"/proc/{pid}/status")
    stat = Path(f"/proc/{pid}/stat")
    if not status.exists() or not stat.exists():
        return 0.0, 0.0
    rss_kb = 0.0
    for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                rss_kb = float(parts[1])
            break
    fields = stat.read_text(encoding="utf-8", errors="replace").split()
    if len(fields) < 15:
        return rss_kb / 1024.0, 0.0
    clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    utime = float(fields[13])
    stime = float(fields[14])
    return rss_kb / 1024.0, (utime + stime) / float(clk_tck)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8810"
    events = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    admin_token = os.getenv("XDR_API_ADMIN_TOKEN", "").strip()
    if not admin_token:
        raise RuntimeError("XDR_API_ADMIN_TOKEN is required")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    status_code, _ = req("GET", f"{base}/healthz")
    if status_code != 200:
        raise RuntimeError(f"healthz failed: status={status_code}")

    run_id = int(time.time())
    source_key = f"bench-edr-{run_id}"
    create_source_start = time.perf_counter()
    status_code, source = req(
        "POST",
        f"{base}/api/v1/sources",
        {
            "source_key": source_key,
            "product": "exkururuedr",
            "display_name": f"Benchmark EDR {run_id}",
            "trust_mode": "legacy",
            "allow_event_ingest": True,
        },
        admin_headers,
    )
    _ = time.perf_counter() - create_source_start
    if status_code != 201:
        raise RuntimeError(f"create source failed: status={status_code}, body={source}")
    source_token = str(source["token"])

    batch_size = int(os.getenv("XDR_BENCH_BATCH_SIZE", "100"))
    batch_size = max(1, min(batch_size, 1000))

    latencies_ms: list[float] = []
    accepted = 0
    failed = 0
    ingest_started = time.perf_counter()
    for i in range(events):
        payload = {
            "schema_version": "common_security_event_v1",
            "event_id": f"bench-evt-{run_id}-{i}",
            "time": "2026-03-11T10:00:00Z",
            "product": "exkururuedr",
            "category": "process",
            "event_type": "SUSPICIOUS_PROCESS",
            "severity": random.choice(["low", "medium", "high"]),
            "score": random.randint(25, 90),
            "labels": ["bench", "e2e"],
            "src_ip": f"192.0.2.{(i % 200) + 1}",
            "dst_ip": "198.51.100.10",
        }
        start = time.perf_counter()
        code, body = req(
            "POST",
            f"{base}/api/v1/events/single",
            payload,
            {"X-Source-Key": source_key, "X-Source-Token": source_token},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        latencies_ms.append(elapsed_ms)
        if code == 202 and int(body.get("inserted", 0)) == 1:
            accepted += 1
        else:
            failed += 1
    ingest_elapsed = time.perf_counter() - ingest_started

    batch_latencies_ms: list[float] = []
    batch_accepted = 0
    batch_failed = 0
    ingest_batch_started = time.perf_counter()
    for i in range(0, events, batch_size):
        batch_events: list[dict] = []
        for j in range(i, min(i + batch_size, events)):
            batch_events.append(
                {
                    "schema_version": "common_security_event_v1",
                    "event_id": f"bench-batch-evt-{run_id}-{j}",
                    "time": "2026-03-11T10:00:00Z",
                    "product": "exkururuedr",
                    "category": "process",
                    "event_type": "SUSPICIOUS_PROCESS",
                    "severity": random.choice(["low", "medium", "high"]),
                    "score": random.randint(25, 90),
                    "labels": ["bench", "e2e", "batch"],
                    "src_ip": f"192.0.2.{(j % 200) + 1}",
                    "dst_ip": "198.51.100.10",
                }
            )
        start = time.perf_counter()
        code, body = req(
            "POST",
            f"{base}/api/v1/events/batch",
            {"events": batch_events},
            {"X-Source-Key": source_key, "X-Source-Token": source_token},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        batch_latencies_ms.append(elapsed_ms)
        if code == 202 and int(body.get("accepted", 0)) == len(batch_events):
            batch_accepted += len(batch_events)
        else:
            batch_failed += len(batch_events)
    ingest_batch_elapsed = time.perf_counter() - ingest_batch_started

    incident_start = time.perf_counter()
    code, incident = req(
        "POST",
        f"{base}/api/v1/incidents",
        {
            "incident_key": f"bench-inc-{run_id}",
            "title": "Benchmark incident",
            "severity": "medium",
            "summary": "benchmark",
            "first_seen": "2026-03-11T10:00:00Z",
            "last_seen": "2026-03-11T10:05:00Z",
            "events": [{"event_id": f"bench-evt-{run_id}-0", "source_key": source_key}],
        },
        admin_headers,
    )
    incident_ms = (time.perf_counter() - incident_start) * 1000.0
    if code != 201:
        raise RuntimeError(f"create incident failed: status={code}, body={incident}")
    incident_id = int(incident["id"])

    case_start = time.perf_counter()
    code, case = req(
        "POST",
        f"{base}/api/v1/cases",
        {"incident_id": incident_id, "title": "Benchmark case", "assignee": "bench", "description": "benchmark"},
        admin_headers,
    )
    case_ms = (time.perf_counter() - case_start) * 1000.0
    if code != 201:
        raise RuntimeError(f"create case failed: status={code}, body={case}")
    case_id = int(case["id"])

    action_start = time.perf_counter()
    code, _action = req(
        "POST",
        f"{base}/api/v1/actions",
        {
            "incident_id": incident_id,
            "case_id": case_id,
            "action_type": "host_isolate",
            "target": "host-bench",
            "requested_by": "bench",
        },
        admin_headers,
    )
    action_ms = (time.perf_counter() - action_start) * 1000.0
    if code != 201:
        raise RuntimeError(f"create action failed: status={code}, body={_action}")

    dispatch_start = time.perf_counter()
    code, _dispatch = req(
        "POST",
        f"{base}/api/v1/orchestrator/dispatch",
        {"limit": 50, "dry_run": True},
        admin_headers,
    )
    dispatch_ms = (time.perf_counter() - dispatch_start) * 1000.0
    if code != 200:
        raise RuntimeError(f"dispatch failed: status={code}, body={_dispatch}")

    pid_env = os.getenv("XDR_BENCH_SERVER_PID", "").strip()
    pid = int(pid_env) if pid_env.isdigit() else None
    rss_mb, cpu_sec = read_proc_usage(pid)

    result = BenchResult(
        total_events=events,
        accepted_events=accepted,
        failed_events=failed,
        loss_events=max(0, events - accepted),
        ingest_avg_ms=statistics.fmean(latencies_ms) if latencies_ms else 0.0,
        ingest_p50_ms=percentile(latencies_ms, 0.50),
        ingest_p95_ms=percentile(latencies_ms, 0.95),
        ingest_eps=(accepted / ingest_elapsed) if ingest_elapsed > 0 else 0.0,
        ingest_batch_avg_ms=statistics.fmean(batch_latencies_ms) if batch_latencies_ms else 0.0,
        ingest_batch_p50_ms=percentile(batch_latencies_ms, 0.50),
        ingest_batch_p95_ms=percentile(batch_latencies_ms, 0.95),
        ingest_batch_eps=(batch_accepted / ingest_batch_elapsed) if ingest_batch_elapsed > 0 else 0.0,
        incident_ms=incident_ms,
        case_ms=case_ms,
        action_ms=action_ms,
        dispatch_ms=dispatch_ms,
        rss_mb=rss_mb,
        cpu_sec=cpu_sec,
    )
    print(json.dumps(result.as_dict(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
