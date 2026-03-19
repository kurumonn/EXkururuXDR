from __future__ import annotations

import csv
import html
import hmac
import os
import re
import time
from hmac import compare_digest
from io import StringIO
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .ipros_adapter import ADAPTER_VERSION, adapt_ipros_event
from .orchestrator import dispatch_requested_actions
from .replay_cache import replay_cache_from_env
from .storage import SourceRecord, XdrStorage
from .storage_facade import XdrReadStorage, XdrWriteStorage
from .validation import ALLOWED_PRODUCTS, validate_event, validate_event_batch


class SourceCreateRequest(BaseModel):
    source_key: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    product: str
    display_name: str = Field(min_length=1, max_length=120)
    trust_mode: str = Field(default="legacy")
    allow_event_ingest: bool = True


class EventBatchRequest(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class ManualEventRequest(BaseModel):
    source_key: str = Field(default="manual-import", min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(default="Manual Import")
    product: str = Field(default="exkururuxdr_import")
    event: dict[str, Any]


class JsonImportRequest(BaseModel):
    source_key: str = Field(default="json-import", min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(default="JSON Import")
    product: str = Field(default="exkururuxdr_import")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=2000)


class CsvImportRequest(BaseModel):
    source_key: str = Field(default="csv-import", min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(default="CSV Import")
    product: str = Field(default="exkururuxdr_import")
    csv_text: str = Field(min_length=1, max_length=2_000_000)


class IncidentCreateRequest(BaseModel):
    incident_key: str = Field(min_length=3, max_length=160)
    title: str = Field(min_length=1, max_length=200)
    severity: str = Field(min_length=1, max_length=20)
    summary: str = ""
    first_seen: str
    last_seen: str
    events: list[dict[str, Any]] = Field(default_factory=list)


class CaseCreateRequest(BaseModel):
    incident_id: int | None = None
    title: str = Field(min_length=1, max_length=200)
    assignee: str = ""
    description: str = ""


class CaseUpdateRequest(BaseModel):
    assignee: str | None = None
    status: str | None = None
    description: str | None = None


class CaseCommentCreateRequest(BaseModel):
    author: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1)


class ActionCreateRequest(BaseModel):
    incident_id: int | None = None
    case_id: int | None = None
    action_type: str = Field(min_length=1, max_length=120)
    target: str = ""
    requested_by: str = Field(min_length=1, max_length=120)


class ActionUpdateRequest(BaseModel):
    status: str = Field(min_length=1, max_length=20)
    result_message: str | None = None


class OrchestratorDispatchRequest(BaseModel):
    limit: int = Field(default=20, ge=1, le=200)
    dry_run: bool | None = None


class IprosExportRequest(BaseModel):
    source_key: str = Field(default="ipros-export", min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(default="IPROS Export")
    ipros_events: list[dict[str, Any]] = Field(min_length=1, max_length=2000)


class EventIncidentLinkRequest(BaseModel):
    incident_id: int
    source_key: str = Field(min_length=1, max_length=80)
    event_id: str = Field(min_length=1, max_length=200)


class RemoteActionCreateRequest(BaseModel):
    source_key: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    action_type: str = Field(min_length=1, max_length=120)
    target: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    requested_by: str = Field(min_length=1, max_length=120)


class RemoteActionAckRequest(BaseModel):
    status: str = Field(min_length=1, max_length=20)
    result_summary: str = ""


class SourceHeartbeatRequest(BaseModel):
    source_key: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(default="IPROS Source")
    product: str = Field(default="exkururuipros")
    health_status: str = Field(min_length=1, max_length=40)
    metrics: dict[str, Any] = Field(default_factory=dict)


class SourceSecurityUpdateRequest(BaseModel):
    trust_mode: str | None = None
    allow_event_ingest: bool | None = None


VALID_REMOTE_ACTION_ACK_STATUSES = {"pending", "in_progress", "completed", "failed"}
VALID_IPROS_REMOTE_ACTION_TYPES = {"block_ip", "unblock_ip", "set_enforcement", "enforcement"}
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,80}$")
_REPLAY_GUARD = replay_cache_from_env(
    namespace="xdr",
    backend_env="XDR_REPLAY_BACKEND",
    redis_url_env="XDR_REDIS_URL",
    fallback_env="XDR_REPLAY_FALLBACK_TO_MEMORY",
    max_items_env="XDR_REPLAY_CACHE_MAX_ITEMS",
    ttl_env="XDR_SOURCE_REPLAY_TTL_SEC",
)


def _parse_csv_events(csv_text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(StringIO(csv_text))
    required_columns = {
        "schema_version",
        "event_id",
        "time",
        "product",
        "category",
        "event_type",
        "severity",
        "score",
        "labels",
    }
    if not reader.fieldnames:
        raise ValueError("csv_header_required")
    missing = sorted(required_columns - set(reader.fieldnames))
    if missing:
        raise ValueError(f"csv_missing_columns:{','.join(missing)}")
    events: list[dict[str, Any]] = []
    for row in reader:
        if not row.get("event_id"):
            continue
        labels = [item.strip() for item in str(row.get("labels", "")).split("|") if item.strip()]
        score_raw = str(row.get("score", "")).strip()
        score = int(score_raw) if score_raw else 0
        event: dict[str, Any] = {
            "schema_version": (row.get("schema_version") or "").strip(),
            "event_id": (row.get("event_id") or "").strip(),
            "time": (row.get("time") or "").strip(),
            "product": (row.get("product") or "").strip(),
            "category": (row.get("category") or "").strip(),
            "event_type": (row.get("event_type") or "").strip(),
            "severity": (row.get("severity") or "").strip(),
            "score": score,
            "labels": labels,
            "src_ip": (row.get("src_ip") or "").strip() or None,
            "dst_ip": (row.get("dst_ip") or "").strip() or None,
        }
        for optional_key in ("host", "user", "process", "parent_process", "raw_ref"):
            value = (row.get(optional_key) or "").strip()
            if value:
                event[optional_key] = value
        events.append(event)
    return events


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "1" if default else "0") or "").strip().lower()
    return raw in {"1", "true", "on", "yes"}


def _env_int(name: str, default: int, min_value: int, max_value: int) -> int:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        value = default
    return max(min_value, min(max_value, value))


def _source_signature_v2(token: str, timestamp: str, body: bytes, nonce: str = "") -> str:
    nonce_value = str(nonce or "").strip()
    if nonce_value:
        payload = f"{timestamp}.{nonce_value}.".encode("utf-8") + body
    else:
        payload = f"{timestamp}.".encode("utf-8") + body
    return hmac.new(key=token.encode("utf-8"), msg=payload, digestmod="sha256").hexdigest()


def _replay_guard_add(raw_key: str, ttl_sec: int) -> bool:
    return _REPLAY_GUARD.add(raw_key, ttl_sec=ttl_sec)


def _render_dashboard(data: dict[str, Any]) -> str:
    summary_cards = (
        f"<div class='card'><h3>Total Events</h3><p>{data['total_events']}</p></div>"
        f"<div class='card'><h3>Sources</h3><p>{data['total_sources']}</p></div>"
        f"<div class='card'><h3>Open Incidents</h3><p>{data['open_incidents']}</p></div>"
        f"<div class='card'><h3>Open Cases</h3><p>{data['open_cases']}</p></div>"
    )
    events_rows = []
    for item in data["recent_events"]:
        payload = item.get("payload", {})
        events_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('created_at', '')))}</td>"
            f"<td>{html.escape(str(item.get('source_key', '')))}</td>"
            f"<td>{html.escape(str(item.get('event_id', '')))}</td>"
            f"<td>{html.escape(str(payload.get('event_type', '')))}</td>"
            f"<td>{html.escape(str(payload.get('severity', '')))}</td>"
            "</tr>"
        )
    sources_rows = []
    for item in data["recent_sources"]:
        sources_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('source_key', '')))}</td>"
            f"<td>{html.escape(str(item.get('product', '')))}</td>"
            f"<td>{html.escape(str(item.get('display_name', '')))}</td>"
            f"<td>{html.escape(str(item.get('status', '')))}</td>"
            f"<td>{html.escape(str(item.get('last_seen', '')))}</td>"
            "</tr>"
        )
    severity_rows = "".join(
        f"<li>{html.escape(k)}: <strong>{v}</strong></li>" for k, v in sorted(data["severity_counts"].items())
    )
    product_rows = "".join(
        f"<li>{html.escape(k)}: <strong>{v}</strong></li>" for k, v in sorted(data["product_counts"].items())
    )
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EXkururuXDR Standalone Dashboard</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 24px; background: #0b1220; color: #eef4ff; overflow-x: hidden; }}
    h1 {{ margin-bottom: 4px; }}
    .sub {{ color: #c3d0e8; margin-bottom: 20px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }}
    .card {{ background: #141f33; border: 1px solid #314970; border-radius: 10px; padding: 12px; overflow-x: auto; -webkit-overflow-scrolling: touch; }}
    .card h3 {{ margin: 0 0 6px; color: #c3d0e8; font-size: 13px; }}
    .card p {{ margin: 0; font-size: 24px; font-weight: 700; }}
    .section {{ margin-top: 20px; }}
    table {{ width: 100%; border-collapse: collapse; background: #141f33; border: 1px solid #314970; border-radius: 10px; overflow: hidden; }}
    th, td {{ padding: 8px 10px; border-bottom: 1px solid #22314e; text-align: left; font-size: 13px; word-break: break-word; overflow-wrap: anywhere; }}
    th {{ color: #c3d0e8; }}
    ul {{ margin: 8px 0 0; padding-left: 18px; }}
    .two {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    @media (max-width: 900px) {{
      body {{ margin: 14px; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
      .two {{ grid-template-columns: 1fr; }}
      .card p {{ font-size: 20px; }}
    }}
    @media (max-width: 600px) {{
      body {{ margin: 10px; }}
      .grid {{ grid-template-columns: 1fr; gap: 8px; }}
      .card {{ padding: 10px; }}
      .card h3 {{ font-size: 12px; }}
      .card p {{ font-size: 18px; }}
      .section {{ margin-top: 14px; }}
      table {{ display: block; overflow-x: auto; white-space: nowrap; }}
      th, td {{ padding: 6px 7px; font-size: 12px; }}
    }}
  </style>
</head>
<body>
  <h1>EXkururuXDR Standalone</h1>
  <div class="sub">JSON/CSV import and manual event operations dashboard</div>
  <div class="grid">{summary_cards}</div>
  <div class="section two">
    <div class="card"><h3>Recent Severity Distribution</h3><ul>{severity_rows or '<li>No data</li>'}</ul></div>
    <div class="card"><h3>Recent Product Distribution</h3><ul>{product_rows or '<li>No data</li>'}</ul></div>
  </div>
  <div class="section">
    <h3>Recent Events</h3>
    <table>
      <thead><tr><th>Created</th><th>Source</th><th>Event ID</th><th>Type</th><th>Severity</th></tr></thead>
      <tbody>{''.join(events_rows) or "<tr><td colspan='5'>No events</td></tr>"}</tbody>
    </table>
  </div>
  <div class="section">
    <h3>Recent Sources</h3>
    <table>
      <thead><tr><th>Source Key</th><th>Product</th><th>Display Name</th><th>Status</th><th>Last Seen</th></tr></thead>
      <tbody>{''.join(sources_rows) or "<tr><td colspan='5'>No sources</td></tr>"}</tbody>
    </table>
  </div>
</body>
</html>
"""


def create_app(db_path: str | Path | None = None) -> FastAPI:
    app = FastAPI(title="EXkururuXDR API", version="0.1.0")
    storage = XdrStorage(db_path or Path("data/xdr.sqlite3"))
    app.state.storage = storage
    app.state.read_storage = XdrReadStorage(storage)
    app.state.write_storage = XdrWriteStorage(storage)

    def get_storage() -> XdrStorage:
        return app.state.storage

    def get_read_storage() -> XdrReadStorage:
        return app.state.read_storage

    def get_write_storage() -> XdrWriteStorage:
        return app.state.write_storage

    def require_admin(authorization: str = Header(default="")) -> None:
        expected = os.getenv("XDR_API_ADMIN_TOKEN", "").strip()
        if not expected:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="admin_auth_not_configured")
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="admin_auth_required")
        provided = authorization[7:].strip()
        if not compare_digest(provided, expected):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin_auth_invalid")

    def ingest_with_source(source: SourceRecord, events: list[dict[str, Any]], storage: XdrStorage) -> dict[str, Any]:
        valid_events, errors = validate_event_batch(events)
        inserted, duplicates = storage.save_events_batch(
            source_key=source.source_key,
            payloads=valid_events,
            touch_source=True,
        )
        return {"accepted": len(events) - len(errors), "inserted": inserted, "duplicates": duplicates, "errors": errors}

    async def require_source(
        request: Request,
        x_source_key: str = Header(default=""),
        x_source_token: str = Header(default=""),
        x_source_timestamp: str = Header(default=""),
        x_source_signature: str = Header(default=""),
        x_source_nonce: str = Header(default=""),
        storage: XdrReadStorage = Depends(get_read_storage),
    ) -> SourceRecord:
        source = storage.authenticate_source(x_source_key, x_source_token)
        if source is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_source_credentials")
        if not source.allow_event_ingest:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="source_ingest_disabled")
        if source.trust_mode == "signed_required":
            if not x_source_timestamp or not x_source_signature:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_signature_required")
            require_nonce = _env_bool("XDR_SOURCE_REQUIRE_NONCE", True)
            nonce = str(x_source_nonce or "").strip()
            if require_nonce and not nonce:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_nonce_required")
            if nonce and not _NONCE_PATTERN.fullmatch(nonce):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_nonce_invalid")
            try:
                timestamp = int(x_source_timestamp)
            except ValueError as exc:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_source_timestamp") from exc
            now = int(time.time())
            if abs(now - timestamp) > 300:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_signature_expired")
            raw_body = await request.body()
            expected_sig = _source_signature_v2(x_source_token, x_source_timestamp, raw_body, nonce=nonce)
            legacy_sig = _source_signature_v2(x_source_token, x_source_timestamp, raw_body, nonce="")
            if not compare_digest(expected_sig, x_source_signature) and not (
                not require_nonce and compare_digest(legacy_sig, x_source_signature)
            ):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_signature_invalid")
            replay_ttl = _env_int("XDR_SOURCE_REPLAY_TTL_SEC", 310, 30, 3600)
            replay_raw = f"{source.source_key}:{request.url.path}:{x_source_timestamp}:{x_source_signature}:{nonce}"
            if not _replay_guard_add(replay_raw, ttl_sec=replay_ttl):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="source_replay_detected")
        return source

    @app.get("/healthz")
    def healthz(storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {"ok": True, "sources": storage.count_sources(), "events": storage.count_events()}

    @app.get("/dashboard", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
    def standalone_dashboard(storage: XdrReadStorage = Depends(get_read_storage)) -> str:
        return _render_dashboard(storage.dashboard_summary())

    @app.get("/api/v1/events", dependencies=[Depends(require_admin)])
    def list_events(
        limit: int = 100,
        source_key: str | None = None,
        storage: XdrReadStorage = Depends(get_read_storage),
    ) -> dict[str, Any]:
        return {"items": storage.list_events(limit=limit, source_key=source_key)}

    @app.get("/api/v1/sources", dependencies=[Depends(require_admin)])
    def list_sources(storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {
            "items": [
                {
                    "source_key": item.source_key,
                    "product": item.product,
                    "display_name": item.display_name,
                    "status": item.status,
                    "last_seen": item.last_seen,
                    "trust_mode": item.trust_mode,
                    "allow_event_ingest": item.allow_event_ingest,
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                }
                for item in storage.list_sources()
            ]
        }

    @app.patch("/api/v1/sources/{source_key}/security", dependencies=[Depends(require_admin)])
    def update_source_security(
        source_key: str,
        body: SourceSecurityUpdateRequest,
        storage: XdrWriteStorage = Depends(get_write_storage),
    ) -> dict[str, Any]:
        try:
            source = storage.update_source_security(
                source_key,
                trust_mode=body.trust_mode,
                allow_event_ingest=body.allow_event_ingest,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="source_not_found") from exc
        return {
            "source_key": source.source_key,
            "status": source.status,
            "trust_mode": source.trust_mode,
            "allow_event_ingest": source.allow_event_ingest,
            "updated_at": source.updated_at,
        }

    @app.post("/api/v1/sources/{source_key}/rotate-token", dependencies=[Depends(require_admin)])
    def rotate_source_token(source_key: str, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        try:
            source = storage.rotate_source_token(source_key)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="source_not_found") from exc
        return {
            "source_key": source.source_key,
            "token": source.token,
            "rotated_at": source.updated_at,
        }

    @app.get("/api/v1/ipros/exports", dependencies=[Depends(require_admin)])
    def list_ipros_exports(limit: int = 100, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {"items": storage.list_export_records(limit=limit)}

    @app.get("/api/v1/ipros/remote-actions", dependencies=[Depends(require_admin)])
    def list_remote_actions(
        source_key: str | None = None,
        status: str | None = None,
        limit: int = 200,
        storage: XdrReadStorage = Depends(get_read_storage),
    ) -> dict[str, Any]:
        return {"items": storage.list_remote_actions(source_key=source_key, status=status, limit=limit)}

    @app.post("/api/v1/ipros/remote-actions", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
    def create_remote_action(body: RemoteActionCreateRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        normalized_action_type = "set_enforcement" if body.action_type == "enforcement" else body.action_type
        if normalized_action_type not in VALID_IPROS_REMOTE_ACTION_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid_action_type:{body.action_type}",
            )
        source = storage.ensure_source(
            source_key=body.source_key,
            product="exkururuipros",
            display_name=f"IPROS {body.source_key}",
        )
        return storage.create_remote_action(
            source_key=source.source_key,
            action_type=normalized_action_type,
            target=body.target,
            payload=body.payload,
            requested_by=body.requested_by,
        )

    @app.post("/api/v1/ipros/remote-actions/{remote_action_id}/ack", dependencies=[Depends(require_admin)])
    def ack_remote_action(
        remote_action_id: int,
        body: RemoteActionAckRequest,
        storage: XdrReadStorage = Depends(get_read_storage),
    ) -> dict[str, Any]:
        if body.status not in VALID_REMOTE_ACTION_ACK_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid_ack_status:{body.status}")
        try:
            return storage.ack_remote_action(
                remote_action_id,
                status=body.status,
                result_summary=body.result_summary,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="remote_action_not_found") from exc

    @app.post("/api/v1/ipros/heartbeat", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_admin)])
    def upsert_ipros_heartbeat(body: SourceHeartbeatRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        source = storage.ensure_source(
            source_key=body.source_key,
            product=body.product,
            display_name=body.display_name,
        )
        record = storage.record_source_heartbeat(
            source_key=source.source_key,
            product=body.product,
            health_status=body.health_status,
            metrics=body.metrics,
        )
        storage.touch_source(source.source_key)
        return {"accepted": 1, "heartbeat": record}

    @app.get("/api/v1/ipros/heartbeat/sources", dependencies=[Depends(require_admin)])
    def list_ipros_source_health(limit: int = 100, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {"items": storage.list_source_health(limit=limit)}

    @app.post("/api/v1/ipros/exports", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_admin)])
    def create_ipros_export(body: IprosExportRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        source = storage.ensure_source(
            source_key=body.source_key,
            product="exkururuipros",
            display_name=body.display_name,
        )
        export_record = storage.create_export_record(
            source_key=source.source_key,
            adapter_version=ADAPTER_VERSION,
            request_payload={"ipros_event_count": len(body.ipros_events)},
        )
        inserted = 0
        duplicates = 0
        failed = 0
        errors: list[dict[str, Any]] = []
        valid_events: list[dict[str, Any]] = []
        for idx, raw in enumerate(body.ipros_events):
            try:
                normalized = adapt_ipros_event(raw)
            except ValueError as exc:
                failed += 1
                errors.append({"index": idx, "event_id": raw.get("event_id") or raw.get("id"), "errors": [str(exc)]})
                continue
            event_errors = validate_event(normalized)
            if event_errors:
                failed += 1
                errors.append({"index": idx, "event_id": normalized.get("event_id"), "errors": event_errors})
                continue
            valid_events.append(normalized)
        inserted, duplicates = storage.save_events_batch(
            source_key=source.source_key,
            payloads=valid_events,
            touch_source=True,
        )
        status_value = "completed" if failed == 0 else ("partial_failed" if inserted > 0 else "failed")
        final_record = storage.finish_export_record(
            export_record["id"],
            status=status_value,
            exported_count=inserted,
            failed_count=failed,
            result_payload={
                "inserted": inserted,
                "duplicates": duplicates,
                "failed": failed,
                "errors": errors,
            },
        )
        return {
            "export": final_record,
            "inserted": inserted,
            "duplicates": duplicates,
            "failed": failed,
            "errors": errors,
        }

    @app.post("/api/v1/sources", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
    def create_source(body: SourceCreateRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        if body.product not in ALLOWED_PRODUCTS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_product")
        try:
            source = storage.register_source(
                source_key=body.source_key,
                product=body.product,
                display_name=body.display_name,
                trust_mode=body.trust_mode,
                allow_event_ingest=body.allow_event_ingest,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="source_key_conflict") from exc
        return {
            "source_key": source.source_key,
            "product": source.product,
            "display_name": source.display_name,
            "token": source.token,
            "status": source.status,
            "trust_mode": source.trust_mode,
            "allow_event_ingest": source.allow_event_ingest,
        }

    @app.post("/api/v1/events/single", status_code=status.HTTP_202_ACCEPTED)
    def ingest_single(
        payload: dict[str, Any],
        source: SourceRecord = Depends(require_source),
        storage: XdrWriteStorage = Depends(get_write_storage),
    ) -> dict[str, Any]:
        errors = validate_event(payload)
        if errors:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"errors": errors})
        inserted, duplicates = storage.save_events_batch(
            source_key=source.source_key,
            payloads=[payload],
            touch_source=True,
        )
        return {"accepted": 1, "inserted": inserted, "duplicates": duplicates}

    @app.post("/api/v1/events/batch", status_code=status.HTTP_202_ACCEPTED)
    def ingest_batch(
        body: EventBatchRequest,
        source: SourceRecord = Depends(require_source),
        storage: XdrWriteStorage = Depends(get_write_storage),
    ) -> dict[str, Any]:
        valid_events, errors = validate_event_batch(body.events)
        inserted, duplicates = storage.save_events_batch(
            source_key=source.source_key,
            payloads=valid_events,
            touch_source=True,
        )
        if errors:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "batch_validation_failed",
                    "accepted": len(body.events) - len(errors),
                    "inserted": inserted,
                    "duplicates": duplicates,
                    "errors": errors,
                },
            )
        return {"accepted": len(body.events), "inserted": inserted, "duplicates": duplicates}

    @app.post("/api/v1/events/manual", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_admin)])
    def ingest_manual_event(body: ManualEventRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        if body.product not in ALLOWED_PRODUCTS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_product")
        source = storage.ensure_source(
            source_key=body.source_key,
            product=body.product,
            display_name=body.display_name,
        )
        result = ingest_with_source(source, [body.event], storage)
        if result["errors"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result)
        return {k: result[k] for k in ("accepted", "inserted", "duplicates")}

    @app.post("/api/v1/import/json", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_admin)])
    def import_json_events(body: JsonImportRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        if body.product not in ALLOWED_PRODUCTS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_product")
        source = storage.ensure_source(
            source_key=body.source_key,
            product=body.product,
            display_name=body.display_name,
        )
        result = ingest_with_source(source, body.events, storage)
        if result["errors"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result)
        return {k: result[k] for k in ("accepted", "inserted", "duplicates")}

    @app.post("/api/v1/import/csv", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_admin)])
    def import_csv_events(body: CsvImportRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        if body.product not in ALLOWED_PRODUCTS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_product")
        try:
            events = _parse_csv_events(body.csv_text)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        source = storage.ensure_source(
            source_key=body.source_key,
            product=body.product,
            display_name=body.display_name,
        )
        result = ingest_with_source(source, events, storage)
        if result["errors"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result)
        return {k: result[k] for k in ("accepted", "inserted", "duplicates")}

    @app.get("/api/v1/incidents", dependencies=[Depends(require_admin)])
    def list_incidents(limit: int = 200, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {"items": storage.list_incidents(limit=limit)}

    @app.get("/api/v1/event-incident-links", dependencies=[Depends(require_admin)])
    def list_event_incident_links(
        incident_id: int | None = None,
        limit: int = 200,
        storage: XdrReadStorage = Depends(get_read_storage),
    ) -> dict[str, Any]:
        return {"items": storage.list_event_incident_links(incident_id=incident_id, limit=limit)}

    @app.post("/api/v1/event-incident-links", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
    def create_event_incident_link(
        body: EventIncidentLinkRequest,
        storage: XdrWriteStorage = Depends(get_write_storage),
    ) -> dict[str, Any]:
        try:
            return storage.link_event_incident(
                incident_id=body.incident_id,
                source_key=body.source_key,
                event_id=body.event_id,
            )
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident_not_found") from exc

    @app.get("/api/v1/incidents/{incident_id}", dependencies=[Depends(require_admin)])
    def get_incident(incident_id: int, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        try:
            return storage.get_incident(incident_id)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident_not_found") from exc

    @app.post("/api/v1/incidents", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
    def create_incident(body: IncidentCreateRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        try:
            return storage.create_incident(
                incident_key=body.incident_key,
                title=body.title,
                severity=body.severity,
                summary=body.summary,
                first_seen=body.first_seen,
                last_seen=body.last_seen,
                events=body.events,
            )
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="incident_key_conflict") from exc

    @app.get("/api/v1/cases", dependencies=[Depends(require_admin)])
    def list_cases(limit: int = 200, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {"items": storage.list_cases(limit=limit)}

    @app.get("/api/v1/cases/{case_id}", dependencies=[Depends(require_admin)])
    def get_case(case_id: int, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        try:
            return storage.get_case(case_id)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case_not_found") from exc

    @app.post("/api/v1/cases", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
    def create_case(body: CaseCreateRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        return storage.create_case(
            incident_id=body.incident_id,
            title=body.title,
            assignee=body.assignee,
            description=body.description,
        )

    @app.patch("/api/v1/cases/{case_id}", dependencies=[Depends(require_admin)])
    def update_case(case_id: int, body: CaseUpdateRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        try:
            return storage.update_case(
                case_id,
                assignee=body.assignee,
                status=body.status,
                description=body.description,
            )
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.post("/api/v1/cases/{case_id}/comments", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
    def add_case_comment(
        case_id: int,
        body: CaseCommentCreateRequest,
        storage: XdrWriteStorage = Depends(get_write_storage),
    ) -> dict[str, Any]:
        try:
            return storage.add_case_comment(case_id=case_id, author=body.author, body=body.body)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case_not_found") from exc

    @app.get("/api/v1/actions", dependencies=[Depends(require_admin)])
    def list_actions(storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {"items": storage.list_actions()}

    @app.get("/api/v1/actions/{action_id}", dependencies=[Depends(require_admin)])
    def get_action(action_id: int, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        try:
            return storage.get_action(action_id)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action_not_found") from exc

    @app.post("/api/v1/actions", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
    def create_action(body: ActionCreateRequest, storage: XdrWriteStorage = Depends(get_write_storage)) -> dict[str, Any]:
        try:
            return storage.create_action(
                incident_id=body.incident_id,
                case_id=body.case_id,
                action_type=body.action_type,
                target=body.target,
                requested_by=body.requested_by,
            )
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident_or_case_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.patch("/api/v1/actions/{action_id}", dependencies=[Depends(require_admin)])
    def update_action(
        action_id: int,
        body: ActionUpdateRequest,
        storage: XdrWriteStorage = Depends(get_write_storage),
    ) -> dict[str, Any]:
        try:
            return storage.update_action(action_id, status=body.status, result_message=body.result_message)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action_not_found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    @app.get("/api/v1/orchestrator/dispatch-logs", dependencies=[Depends(require_admin)])
    def list_dispatch_logs(limit: int = 100, storage: XdrReadStorage = Depends(get_read_storage)) -> dict[str, Any]:
        return {"items": storage.list_dispatch_logs(limit=limit)}

    @app.post("/api/v1/orchestrator/dispatch", dependencies=[Depends(require_admin)])
    def run_dispatch(
        body: OrchestratorDispatchRequest,
        storage: XdrWriteStorage = Depends(get_write_storage),
    ) -> dict[str, Any]:
        return dispatch_requested_actions(storage=storage, limit=body.limit, dry_run=body.dry_run)

    return app


app = create_app()
