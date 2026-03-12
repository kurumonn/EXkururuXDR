#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request


def req(method: str, url: str, payload: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    data = None
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url=url, method=method, data=data, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            body = response.read().decode("utf-8")
            return response.getcode(), json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        parsed = {}
        if body:
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"raw": body}
        return exc.code, parsed


def assert_status(status: int, expected: int, body: dict, step: str) -> None:
    if status != expected:
        raise RuntimeError(f"{step}: expected {expected}, got {status}, body={body}")


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8810"
    admin_token = os.getenv("XDR_API_ADMIN_TOKEN", "").strip()
    if not admin_token:
        raise RuntimeError("XDR_API_ADMIN_TOKEN is required")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    run_id = int(time.time())
    source_key = f"smoke-edr-{run_id}"
    incident_key = f"smoke-inc-{run_id}"

    status, body = req("GET", f"{base}/healthz", payload=None, headers={})
    assert_status(status, 200, body, "healthz")
    print("[OK] healthz")

    status, body = req(
        "POST",
        f"{base}/api/v1/sources",
        {"source_key": source_key, "product": "exkururuedr", "display_name": f"Smoke EDR {run_id}"},
        admin_headers,
    )
    assert_status(status, 201, body, "create_source")
    source_token = body["token"]
    print("[OK] create_source")

    status, body = req(
        "POST",
        f"{base}/api/v1/events/single",
        {
            "schema_version": "common_security_event_v1",
            "event_id": f"smoke-evt-{run_id}",
            "time": "2026-03-11T10:00:00Z",
            "product": "exkururuedr",
            "category": "process",
            "event_type": "SUSPICIOUS_PROCESS",
            "severity": "high",
            "score": 87,
            "labels": ["powershell", "encoded-command"],
            "src_ip": "192.0.2.10",
            "dst_ip": None,
        },
        {"X-Source-Key": source_key, "X-Source-Token": source_token},
    )
    assert_status(status, 202, body, "ingest_single")
    print("[OK] ingest_single")

    status, body = req(
        "POST",
        f"{base}/api/v1/incidents",
        {
            "incident_key": incident_key,
            "title": "Smoke Incident",
            "severity": "high",
            "summary": "smoke",
            "first_seen": "2026-03-11T10:00:00Z",
            "last_seen": "2026-03-11T10:04:00Z",
            "events": [{"event_id": f"smoke-evt-{run_id}", "source_key": source_key}],
        },
        admin_headers,
    )
    assert_status(status, 201, body, "create_incident")
    incident_id = body["id"]
    print("[OK] create_incident")

    status, body = req(
        "POST",
        f"{base}/api/v1/cases",
        {"incident_id": incident_id, "title": "Smoke Case", "assignee": "smoke-user", "description": "smoke"},
        admin_headers,
    )
    assert_status(status, 201, body, "create_case")
    case_id = body["id"]
    print("[OK] create_case")

    status, body = req(
        "POST",
        f"{base}/api/v1/actions",
        {
            "incident_id": incident_id,
            "case_id": case_id,
            "action_type": "host_isolate",
            "target": "host-192-0-2-10",
            "requested_by": "smoke-user",
        },
        admin_headers,
    )
    assert_status(status, 201, body, "create_action")
    action_id = body["id"]
    print("[OK] create_action")

    status, body = req(
        "PATCH",
        f"{base}/api/v1/actions/{action_id}",
        {"status": "completed", "result_message": "smoke completed"},
        admin_headers,
    )
    assert_status(status, 200, body, "complete_action")
    print("[OK] complete_action")
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
