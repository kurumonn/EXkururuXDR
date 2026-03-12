from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

from fastapi.testclient import TestClient

from exkururuxdr.api import create_app


def build_client(tmp_path):
    os.environ["XDR_API_ADMIN_TOKEN"] = "test-admin-token"
    app = create_app(tmp_path / "xdr.sqlite3")
    return TestClient(app)


def admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-admin-token"}


def source_signature_headers(token: str, payload: dict) -> dict[str, str]:
    ts = str(int(time.time()))
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(token.encode("utf-8"), f"{ts}.".encode("utf-8") + raw, hashlib.sha256).hexdigest()
    return {"X-Source-Timestamp": ts, "X-Source-Signature": sig}


def sample_event(event_id: str = "evt-1") -> dict:
    return {
        "schema_version": "common_security_event_v1",
        "event_id": event_id,
        "time": "2026-03-11T10:00:00Z",
        "product": "exkururuedr",
        "category": "process",
        "event_type": "SUSPICIOUS_PROCESS",
        "severity": "high",
        "score": 87,
        "labels": ["powershell", "encoded-command"],
        "src_ip": "192.0.2.10",
        "dst_ip": None,
    }


def register_source(client: TestClient) -> dict:
    response = client.post(
        "/api/v1/sources",
        json={
            "source_key": "edr-lab-01",
            "product": "exkururuedr",
            "display_name": "EDR Lab 01",
        },
        headers=admin_headers(),
    )
    assert response.status_code == 201
    return response.json()


def test_create_source_and_list_sources(tmp_path) -> None:
    client = build_client(tmp_path)
    created = register_source(client)
    assert created["source_key"] == "edr-lab-01"
    assert created["token"]

    listing = client.get("/api/v1/sources", headers=admin_headers())
    assert listing.status_code == 200
    assert listing.json()["items"][0]["source_key"] == "edr-lab-01"
    assert listing.json()["items"][0]["status"] == "active"


def test_admin_endpoint_requires_bearer_token(tmp_path) -> None:
    client = build_client(tmp_path)
    response = client.get("/api/v1/incidents")
    assert response.status_code == 401
    assert response.json()["detail"] == "admin_auth_required"


def test_create_source_rejects_invalid_trust_mode(tmp_path) -> None:
    client = build_client(tmp_path)
    response = client.post(
        "/api/v1/sources",
        json={
            "source_key": "bad-trust-01",
            "product": "exkururuedr",
            "display_name": "Bad Trust",
            "trust_mode": "invalid",
        },
        headers=admin_headers(),
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_source_trust_mode"


def test_ingest_single_persists_event_and_updates_last_seen(tmp_path) -> None:
    client = build_client(tmp_path)
    source = register_source(client)
    response = client.post(
        "/api/v1/events/single",
        json=sample_event(),
        headers={"X-Source-Key": source["source_key"], "X-Source-Token": source["token"]},
    )
    assert response.status_code == 202
    assert response.json()["inserted"] == 1

    listing = client.get("/api/v1/sources", headers=admin_headers())
    assert listing.json()["items"][0]["last_seen"] is not None


def test_ingest_batch_rejects_invalid_payload(tmp_path) -> None:
    client = build_client(tmp_path)
    source = register_source(client)
    bad_event = sample_event("evt-bad")
    del bad_event["labels"]
    response = client.post(
        "/api/v1/events/batch",
        json={"events": [sample_event("evt-good"), bad_event]},
        headers={"X-Source-Key": source["source_key"], "X-Source-Token": source["token"]},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["inserted"] == 1
    assert detail["errors"][0]["event_id"] == "evt-bad"


def test_incident_case_action_flow(tmp_path) -> None:
    client = build_client(tmp_path)

    incident_response = client.post(
        "/api/v1/incidents",
        json={
            "incident_key": "inc-001",
            "title": "Cross-product persistence",
            "severity": "high",
            "summary": "NDR and EDR correlation matched",
            "first_seen": "2026-03-11T10:00:00Z",
            "last_seen": "2026-03-11T10:04:00Z",
            "events": [
                {"event_id": "evt-1", "source_key": "ndr-01", "event_type": "BEACONING"},
                {"event_id": "evt-2", "source_key": "edr-01", "event_type": "PERSISTENCE_REGISTRY_RUNKEY"},
            ],
        },
        headers=admin_headers(),
    )
    assert incident_response.status_code == 201
    incident = incident_response.json()
    assert incident["incident_key"] == "inc-001"
    assert len(incident["events"]) == 2

    list_incidents = client.get("/api/v1/incidents", headers=admin_headers())
    assert list_incidents.status_code == 200
    assert list_incidents.json()["items"][0]["incident_key"] == "inc-001"

    case_response = client.post(
        "/api/v1/cases",
        json={
            "incident_id": incident["id"],
            "title": "Investigate persistence",
            "assignee": "analyst-a",
            "description": "Initial triage",
        },
        headers=admin_headers(),
    )
    assert case_response.status_code == 201
    case = case_response.json()
    assert case["incident_id"] == incident["id"]
    assert case["status"] == "open"

    updated_case = client.patch(
        f"/api/v1/cases/{case['id']}",
        json={"status": "investigating", "assignee": "analyst-b"},
        headers=admin_headers(),
    )
    assert updated_case.status_code == 200
    assert updated_case.json()["status"] == "investigating"
    assert updated_case.json()["assignee"] == "analyst-b"

    comment_response = client.post(
        f"/api/v1/cases/{case['id']}/comments",
        json={"author": "analyst-b", "body": "Confirmed suspicious registry run key."},
        headers=admin_headers(),
    )
    assert comment_response.status_code == 201

    case_detail = client.get(f"/api/v1/cases/{case['id']}", headers=admin_headers())
    assert case_detail.status_code == 200
    assert len(case_detail.json()["comments"]) == 1

    action_response = client.post(
        "/api/v1/actions",
        json={
            "incident_id": incident["id"],
            "case_id": case["id"],
            "action_type": "host_isolate",
            "target": "host-192-0-2-10",
            "requested_by": "analyst-b",
        },
        headers=admin_headers(),
    )
    assert action_response.status_code == 201
    action = action_response.json()
    assert action["status"] == "requested"

    updated_action = client.patch(
        f"/api/v1/actions/{action['id']}",
        json={"status": "completed", "result_message": "isolation command delivered"},
        headers=admin_headers(),
    )
    assert updated_action.status_code == 200
    assert updated_action.json()["status"] == "completed"


def test_standalone_manual_json_csv_import_and_dashboard(tmp_path) -> None:
    client = build_client(tmp_path)

    manual_response = client.post(
        "/api/v1/events/manual",
        json={
            "source_key": "manual-import",
            "display_name": "Manual Import",
            "product": "exkururuxdr_import",
                "event": {
                    "schema_version": "common_security_event_v1",
                    "event_id": "manual-evt-1",
                    "time": "2026-03-11T10:10:00Z",
                    "product": "exkururuxdr_import",
                    "category": "correlation",
                    "event_type": "MANUAL_NOTE",
                    "severity": "low",
                    "score": 20,
                    "labels": ["manual", "note"],
                    "src_ip": "192.0.2.20",
                "dst_ip": None,
            },
        },
        headers=admin_headers(),
    )
    assert manual_response.status_code == 202
    assert manual_response.json()["inserted"] == 1

    json_response = client.post(
        "/api/v1/import/json",
        json={
            "source_key": "json-import",
            "display_name": "JSON Import",
            "product": "exkururuxdr_import",
            "events": [
                {
                    "schema_version": "common_security_event_v1",
                    "event_id": "json-evt-1",
                    "time": "2026-03-11T10:11:00Z",
                    "product": "exkururuxdr_import",
                    "category": "network",
                    "event_type": "PORT_SCAN",
                    "severity": "medium",
                    "score": 55,
                    "labels": ["import", "json"],
                    "src_ip": "192.0.2.21",
                    "dst_ip": "198.51.100.10",
                }
            ],
        },
        headers=admin_headers(),
    )
    assert json_response.status_code == 202
    assert json_response.json()["inserted"] == 1

    csv_payload = "\n".join(
        [
            "schema_version,event_id,time,product,category,event_type,severity,score,labels,src_ip,dst_ip,host,user,process,parent_process,raw_ref",
            "common_security_event_v1,csv-evt-1,2026-03-11T10:12:00Z,exkururuxdr_import,process,SUSPICIOUS_PROCESS,high,80,import|csv,192.0.2.22,198.51.100.11,host-01,user-01,cmd.exe,explorer.exe,import://csv/1",
        ]
    )
    csv_response = client.post(
        "/api/v1/import/csv",
        json={
            "source_key": "csv-import",
            "display_name": "CSV Import",
            "product": "exkururuxdr_import",
            "csv_text": csv_payload,
        },
        headers=admin_headers(),
    )
    assert csv_response.status_code == 202
    assert csv_response.json()["inserted"] == 1

    events_response = client.get("/api/v1/events?limit=10", headers=admin_headers())
    assert events_response.status_code == 200
    assert len(events_response.json()["items"]) >= 3

    dashboard_response = client.get("/dashboard", headers=admin_headers())
    assert dashboard_response.status_code == 200
    assert "EXkururuXDR Standalone" in dashboard_response.text


def test_orchestrator_dispatch_dry_run_and_logs(tmp_path) -> None:
    client = build_client(tmp_path)
    incident = client.post(
        "/api/v1/incidents",
        json={
            "incident_key": "inc-orch-1",
            "title": "Need response action",
            "severity": "high",
            "summary": "dispatch test",
            "first_seen": "2026-03-11T10:00:00Z",
            "last_seen": "2026-03-11T10:01:00Z",
            "events": [],
        },
        headers=admin_headers(),
    ).json()
    case = client.post(
        "/api/v1/cases",
        json={
            "incident_id": incident["id"],
            "title": "IR case",
            "assignee": "analyst-a",
            "description": "dispatch test",
        },
        headers=admin_headers(),
    ).json()

    isolate_action = client.post(
        "/api/v1/actions",
        json={
            "incident_id": incident["id"],
            "case_id": case["id"],
            "action_type": "host_isolate",
            "target": "host-1",
            "requested_by": "analyst-a",
        },
        headers=admin_headers(),
    )
    assert isolate_action.status_code == 201

    unsupported_action = client.post(
        "/api/v1/actions",
        json={
            "incident_id": incident["id"],
            "case_id": case["id"],
            "action_type": "notify_owner",
            "target": "mailbox",
            "requested_by": "analyst-a",
        },
        headers=admin_headers(),
    )
    assert unsupported_action.status_code == 201

    dispatch_response = client.post(
        "/api/v1/orchestrator/dispatch",
        json={"limit": 10, "dry_run": True},
        headers=admin_headers(),
    )
    assert dispatch_response.status_code == 200
    dispatch_body = dispatch_response.json()
    assert dispatch_body["total"] >= 2
    assert dispatch_body["dispatched"] >= 1
    assert dispatch_body["skipped"] >= 1
    assert dispatch_body["dry_run"] is True

    logs_response = client.get("/api/v1/orchestrator/dispatch-logs?limit=10", headers=admin_headers())
    assert logs_response.status_code == 200
    assert len(logs_response.json()["items"]) >= 2

    action_detail = client.get(f"/api/v1/actions/{isolate_action.json()['id']}", headers=admin_headers())
    assert action_detail.status_code == 200
    assert action_detail.json()["status"] == "completed"


def test_ipros_export_and_event_incident_link(tmp_path) -> None:
    client = build_client(tmp_path)

    export_response = client.post(
        "/api/v1/ipros/exports",
        json={
            "source_key": "ipros-sync",
            "display_name": "IPROS Sync",
            "ipros_events": [
                {
                    "id": "ipros-evt-1",
                    "timestamp": "2026-03-11T10:20:00Z",
                    "type": "NDR_ALERT",
                    "severity": "high",
                    "src_ip": "192.0.2.30",
                    "dst_ip": "198.51.100.30",
                    "labels": ["ipros", "ndr"],
                }
            ],
        },
        headers=admin_headers(),
    )
    assert export_response.status_code == 202
    export_body = export_response.json()
    assert export_body["inserted"] == 1
    assert export_body["failed"] == 0
    assert export_body["export"]["status"] == "completed"

    exports_list = client.get("/api/v1/ipros/exports?limit=5", headers=admin_headers())
    assert exports_list.status_code == 200
    assert len(exports_list.json()["items"]) >= 1

    incident_response = client.post(
        "/api/v1/incidents",
        json={
            "incident_key": "inc-ipros-1",
            "title": "IPROS linked incident",
            "severity": "high",
            "summary": "linked from export event",
            "first_seen": "2026-03-11T10:20:00Z",
            "last_seen": "2026-03-11T10:20:00Z",
            "events": [{"event_id": "ipros-evt-1", "source_key": "ipros-sync"}],
        },
        headers=admin_headers(),
    )
    assert incident_response.status_code == 201
    incident = incident_response.json()

    links_response = client.get(
        f"/api/v1/event-incident-links?incident_id={incident['id']}",
        headers=admin_headers(),
    )
    assert links_response.status_code == 200
    assert len(links_response.json()["items"]) >= 1
    link = links_response.json()["items"][0]
    assert link["event_id"] == "ipros-evt-1"
    assert link["source_key"] == "ipros-sync"
    assert link["security_event_id"] is not None


def test_ipros_remote_action_and_heartbeat_flow(tmp_path) -> None:
    client = build_client(tmp_path)

    create_action = client.post(
        "/api/v1/ipros/remote-actions",
        json={
            "source_key": "ipros-edge-01",
            "action_type": "block_ip",
            "target": "203.0.113.99",
            "payload": {"duration_sec": 3600, "reason": "xdr correlation"},
            "requested_by": "xdr-analyst",
        },
        headers=admin_headers(),
    )
    assert create_action.status_code == 201
    action = create_action.json()
    assert action["status"] == "pending"
    assert action["source_key"] == "ipros-edge-01"

    pending_actions = client.get(
        "/api/v1/ipros/remote-actions?source_key=ipros-edge-01&status=pending",
        headers=admin_headers(),
    )
    assert pending_actions.status_code == 200
    assert len(pending_actions.json()["items"]) >= 1

    ack_action = client.post(
        f"/api/v1/ipros/remote-actions/{action['id']}/ack",
        json={"status": "completed", "result_summary": "blocked in edge firewall"},
        headers=admin_headers(),
    )
    assert ack_action.status_code == 200
    assert ack_action.json()["status"] == "completed"
    assert "blocked" in ack_action.json()["result_summary"]

    hb_response = client.post(
        "/api/v1/ipros/heartbeat",
        json={
            "source_key": "ipros-edge-01",
            "display_name": "IPROS Edge 01",
            "product": "exkururuipros",
            "health_status": "healthy",
            "metrics": {"queue_depth": 0, "drop_rate": 0.0, "version": "1.0.0"},
        },
        headers=admin_headers(),
    )
    assert hb_response.status_code == 202
    assert hb_response.json()["heartbeat"]["health_status"] == "healthy"

    health_list = client.get("/api/v1/ipros/heartbeat/sources?limit=10", headers=admin_headers())
    assert health_list.status_code == 200
    assert len(health_list.json()["items"]) >= 1
    assert health_list.json()["items"][0]["source_key"] == "ipros-edge-01"


def test_signed_required_source_contract_and_rotate_token(tmp_path) -> None:
    client = build_client(tmp_path)
    create = client.post(
        "/api/v1/sources",
        json={
            "source_key": "signed-edr-01",
            "product": "exkururuedr",
            "display_name": "Signed EDR",
            "trust_mode": "signed_required",
            "allow_event_ingest": True,
        },
        headers=admin_headers(),
    )
    assert create.status_code == 201
    token = create.json()["token"]

    payload = sample_event("signed-evt-1")
    no_sig = client.post(
        "/api/v1/events/single",
        json=payload,
        headers={"X-Source-Key": "signed-edr-01", "X-Source-Token": token},
    )
    assert no_sig.status_code == 401

    sig_headers = source_signature_headers(token, payload)
    ok = client.post(
        "/api/v1/events/single",
        json=payload,
        headers={"X-Source-Key": "signed-edr-01", "X-Source-Token": token, **sig_headers},
    )
    assert ok.status_code == 202

    rotated = client.post("/api/v1/sources/signed-edr-01/rotate-token", headers=admin_headers())
    assert rotated.status_code == 200
    new_token = rotated.json()["token"]
    assert new_token and new_token != token

    old_sig_headers = source_signature_headers(token, payload)
    old_try = client.post(
        "/api/v1/events/single",
        json=payload,
        headers={"X-Source-Key": "signed-edr-01", "X-Source-Token": token, **old_sig_headers},
    )
    assert old_try.status_code == 401
