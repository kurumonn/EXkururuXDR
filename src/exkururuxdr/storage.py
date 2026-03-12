from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SourceRecord:
    source_key: str
    product: str
    display_name: str
    token: str
    status: str
    last_seen: str | None
    trust_mode: str
    allow_event_ingest: bool
    created_at: str
    updated_at: str


class XdrStorage:
    VALID_CASE_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
    VALID_ACTION_STATUSES = {"requested", "in_progress", "completed", "failed"}
    VALID_REMOTE_ACTION_STATUSES = {"pending", "in_progress", "completed", "failed"}
    VALID_SOURCE_TRUST_MODES = {"legacy", "signed_required"}

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA temp_store = MEMORY")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    source_key TEXT PRIMARY KEY,
                    product TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    token TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    last_seen TEXT NULL,
                    trust_mode TEXT NOT NULL DEFAULT 'legacy',
                    allow_event_ingest INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(source_key) REFERENCES sources(source_key)
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_key TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    summary TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incident_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    source_key TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );

                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NULL,
                    title TEXT NOT NULL,
                    assignee TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );

                CREATE TABLE IF NOT EXISTS case_comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NULL,
                    case_id INTEGER NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'requested',
                    requested_by TEXT NOT NULL DEFAULT '',
                    result_message TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id),
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS action_dispatch_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_id INTEGER NOT NULL,
                    connector TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    dry_run INTEGER NOT NULL DEFAULT 0,
                    http_status INTEGER NULL,
                    response_body TEXT NOT NULL DEFAULT '',
                    error_message TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(action_id) REFERENCES actions(id)
                );

                CREATE TABLE IF NOT EXISTS xdr_exports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_key TEXT NOT NULL,
                    adapter_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    exported_count INTEGER NOT NULL DEFAULT 0,
                    failed_count INTEGER NOT NULL DEFAULT 0,
                    request_json TEXT NOT NULL DEFAULT '{}',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS event_incident_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    source_key TEXT NOT NULL,
                    security_event_id INTEGER NULL,
                    linked_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id),
                    FOREIGN KEY(security_event_id) REFERENCES security_events(id),
                    UNIQUE(incident_id, source_key, event_id)
                );

                CREATE TABLE IF NOT EXISTS remote_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_key TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    requested_by TEXT NOT NULL DEFAULT '',
                    result_summary TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS source_heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_key TEXT NOT NULL,
                    product TEXT NOT NULL,
                    health_status TEXT NOT NULL,
                    metrics_json TEXT NOT NULL DEFAULT '{}',
                    last_seen TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS xdr_event_unique_idx
                ON security_events(source_key, event_id);

                CREATE INDEX IF NOT EXISTS xdr_event_source_created_idx
                ON security_events(source_key, created_at);

                CREATE INDEX IF NOT EXISTS xdr_event_source_id_idx
                ON security_events(source_key, id DESC);

                CREATE INDEX IF NOT EXISTS xdr_incident_status_updated_idx
                ON incidents(status, updated_at);

                CREATE INDEX IF NOT EXISTS xdr_incident_updated_idx
                ON incidents(updated_at DESC, id DESC);

                CREATE INDEX IF NOT EXISTS xdr_incident_event_incident_idx
                ON incident_events(incident_id, created_at);

                CREATE INDEX IF NOT EXISTS xdr_incident_event_incident_id_idx
                ON incident_events(incident_id, id);

                CREATE INDEX IF NOT EXISTS xdr_case_status_updated_idx
                ON cases(status, updated_at);

                CREATE INDEX IF NOT EXISTS xdr_case_updated_idx
                ON cases(updated_at DESC, id DESC);

                CREATE INDEX IF NOT EXISTS xdr_case_comment_case_idx
                ON case_comments(case_id, created_at);

                CREATE INDEX IF NOT EXISTS xdr_case_comment_case_id_idx
                ON case_comments(case_id, id DESC);

                CREATE INDEX IF NOT EXISTS xdr_action_status_updated_idx
                ON actions(status, updated_at);

                CREATE INDEX IF NOT EXISTS xdr_action_updated_idx
                ON actions(updated_at DESC, id DESC);

                CREATE INDEX IF NOT EXISTS xdr_dispatch_action_created_idx
                ON action_dispatch_logs(action_id, created_at);

                CREATE INDEX IF NOT EXISTS xdr_exports_source_updated_idx
                ON xdr_exports(source_key, updated_at);

                CREATE INDEX IF NOT EXISTS xdr_event_incident_incident_idx
                ON event_incident_links(incident_id, linked_at);

                CREATE INDEX IF NOT EXISTS xdr_event_incident_linked_idx
                ON event_incident_links(linked_at DESC, id DESC);

                CREATE INDEX IF NOT EXISTS xdr_remote_action_status_created_idx
                ON remote_actions(status, created_at);

                CREATE INDEX IF NOT EXISTS xdr_remote_action_source_status_idx
                ON remote_actions(source_key, status, created_at);

                CREATE INDEX IF NOT EXISTS xdr_source_heartbeat_source_seen_idx
                ON source_heartbeats(source_key, last_seen);

                CREATE INDEX IF NOT EXISTS xdr_sources_updated_idx
                ON sources(updated_at DESC, source_key ASC);
                """
            )
            source_columns = {row["name"] for row in conn.execute("PRAGMA table_info(sources)").fetchall()}
            if "trust_mode" not in source_columns:
                conn.execute("ALTER TABLE sources ADD COLUMN trust_mode TEXT NOT NULL DEFAULT 'legacy'")
            if "allow_event_ingest" not in source_columns:
                conn.execute("ALTER TABLE sources ADD COLUMN allow_event_ingest INTEGER NOT NULL DEFAULT 1")

    def register_source(
        self,
        *,
        source_key: str,
        product: str,
        display_name: str,
        trust_mode: str = "legacy",
        allow_event_ingest: bool = True,
    ) -> SourceRecord:
        if trust_mode not in self.VALID_SOURCE_TRUST_MODES:
            raise ValueError("invalid_source_trust_mode")
        now = utc_now()
        token = secrets.token_urlsafe(24)
        token_hash = self._hash_token(token)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO sources (
                    source_key, product, display_name, token, status, last_seen, trust_mode, allow_event_ingest, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'active', NULL, ?, ?, ?, ?)
                """,
                (source_key, product, display_name, token_hash, trust_mode, 1 if allow_event_ingest else 0, now, now),
            )
        source = self.get_source(source_key)
        return SourceRecord(
            source_key=source.source_key,
            product=source.product,
            display_name=source.display_name,
            token=token,
            status=source.status,
            last_seen=source.last_seen,
            trust_mode=source.trust_mode,
            allow_event_ingest=source.allow_event_ingest,
            created_at=source.created_at,
            updated_at=source.updated_at,
        )

    def list_sources(self) -> list[SourceRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT source_key, product, display_name, token, status, last_seen, created_at, updated_at
                , trust_mode, allow_event_ingest
                FROM sources
                ORDER BY source_key
                """
            ).fetchall()
        return [self._row_to_source(row) for row in rows]

    def get_source(self, source_key: str) -> SourceRecord:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT source_key, product, display_name, token, status, last_seen, created_at, updated_at
                , trust_mode, allow_event_ingest
                FROM sources
                WHERE source_key = ?
                """,
                (source_key,),
            ).fetchone()
        if row is None:
            raise KeyError(source_key)
        return self._row_to_source(row)

    def authenticate_source(self, source_key: str, token: str) -> SourceRecord | None:
        try:
            source = self.get_source(source_key)
        except KeyError:
            return None
        if source.status != "active":
            return None
        if self._verify_token(stored=source.token, provided=token):
            # Legacy compatibility: migrate plain token to hash after successful authentication.
            if not self._is_hash_value(source.token):
                now = utc_now()
                with self.connect() as conn:
                    conn.execute(
                        "UPDATE sources SET token = ?, updated_at = ? WHERE source_key = ?",
                        (self._hash_token(token), now, source_key),
                    )
            return source
        return None

    def touch_source(self, source_key: str) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE sources SET last_seen = ?, updated_at = ? WHERE source_key = ?",
                (now, now, source_key),
            )

    def update_source_security(
        self,
        source_key: str,
        *,
        trust_mode: str | None = None,
        allow_event_ingest: bool | None = None,
    ) -> SourceRecord:
        updates: list[str] = []
        params: list[Any] = []
        if trust_mode is not None:
            if trust_mode not in self.VALID_SOURCE_TRUST_MODES:
                raise ValueError("invalid_source_trust_mode")
            updates.append("trust_mode = ?")
            params.append(trust_mode)
        if allow_event_ingest is not None:
            updates.append("allow_event_ingest = ?")
            params.append(1 if allow_event_ingest else 0)
        if not updates:
            return self.get_source(source_key)
        updates.append("updated_at = ?")
        params.append(utc_now())
        params.append(source_key)
        with self.connect() as conn:
            conn.execute(f"UPDATE sources SET {', '.join(updates)} WHERE source_key = ?", params)
        return self.get_source(source_key)

    def rotate_source_token(self, source_key: str) -> SourceRecord:
        source = self.get_source(source_key)
        new_token = secrets.token_urlsafe(24)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE sources SET token = ?, updated_at = ? WHERE source_key = ?",
                (self._hash_token(new_token), now, source_key),
            )
        return SourceRecord(
            source_key=source.source_key,
            product=source.product,
            display_name=source.display_name,
            token=new_token,
            status=source.status,
            last_seen=source.last_seen,
            trust_mode=source.trust_mode,
            allow_event_ingest=source.allow_event_ingest,
            created_at=source.created_at,
            updated_at=now,
        )

    def save_event(self, *, source_key: str, payload: dict[str, Any]) -> bool:
        inserted, _ = self.save_events_batch(source_key=source_key, payloads=[payload])
        return inserted > 0

    def ensure_source(self, *, source_key: str, product: str, display_name: str) -> SourceRecord:
        try:
            return self.get_source(source_key)
        except KeyError:
            return self.register_source(source_key=source_key, product=product, display_name=display_name)

    def count_events(self) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM security_events").fetchone()
        return int(row["c"])

    def count_sources(self) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM sources").fetchone()
        return int(row["c"])

    def list_events(self, *, limit: int = 100, source_key: str | None = None) -> list[dict[str, Any]]:
        sql = """
            SELECT id, event_id, source_key, payload_json, created_at
            FROM security_events
        """
        params: list[Any] = []
        if source_key:
            sql += " WHERE source_key = ?"
            params.append(source_key)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "id": row["id"],
                "event_id": row["event_id"],
                "source_key": row["source_key"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def save_events_batch(
        self,
        *,
        source_key: str,
        payloads: list[dict[str, Any]],
        touch_source: bool = False,
    ) -> tuple[int, int]:
        if not payloads:
            return 0, 0
        now = utc_now()
        if len(payloads) < 256:
            rows = [
                (
                    str(payload.get("event_id", "")).strip(),
                    source_key,
                    self._dump_json(payload),
                    now,
                )
                for payload in payloads
            ]
        else:
            event_ids = [str(payload.get("event_id", "")).strip() for payload in payloads]
            unique_event_ids = set(event_ids)
            if len(unique_event_ids) == len(event_ids):
                rows = [
                    (event_ids[idx], source_key, self._dump_json(payloads[idx]), now)
                    for idx in range(len(payloads))
                ]
            else:
                # Keep first event for each duplicate event_id and skip local duplicates.
                # This preserves INSERT OR IGNORE semantics while avoiding redundant JSON serialization.
                seen_event_ids: set[str] = set()
                rows = []
                for idx, payload in enumerate(payloads):
                    event_id = event_ids[idx]
                    if event_id in seen_event_ids:
                        continue
                    seen_event_ids.add(event_id)
                    rows.append((event_id, source_key, self._dump_json(payload), now))
        with self.connect() as conn:
            before_changes = conn.total_changes
            if rows:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO security_events (event_id, source_key, payload_json, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    rows,
                )
            inserted = int(conn.total_changes - before_changes)
            if touch_source:
                conn.execute(
                    "UPDATE sources SET last_seen = ?, updated_at = ? WHERE source_key = ?",
                    (now, now, source_key),
                )
        duplicates = len(payloads) - inserted
        return inserted, duplicates

    def dashboard_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            total_events = int(conn.execute("SELECT COUNT(*) AS c FROM security_events").fetchone()["c"])
            total_sources = int(conn.execute("SELECT COUNT(*) AS c FROM sources").fetchone()["c"])
            open_incidents = int(
                conn.execute("SELECT COUNT(*) AS c FROM incidents WHERE status IN ('open', 'investigating')").fetchone()[
                    "c"
                ]
            )
            open_cases = int(
                conn.execute("SELECT COUNT(*) AS c FROM cases WHERE status IN ('open', 'investigating')").fetchone()["c"]
            )
            source_rows = conn.execute(
                """
                SELECT source_key, product, display_name, status, last_seen
                FROM sources
                ORDER BY updated_at DESC, source_key ASC
                LIMIT 20
                """
            ).fetchall()
            recent_event_rows = conn.execute(
                """
                SELECT id, event_id, source_key, payload_json, created_at
                FROM security_events
                ORDER BY id DESC
                LIMIT 20
                """
            ).fetchall()
            try:
                severity_rows = conn.execute(
                    """
                    SELECT COALESCE(json_extract(payload_json, '$.severity'), 'unknown') AS value, COUNT(*) AS c
                    FROM (
                        SELECT payload_json
                        FROM security_events
                        ORDER BY id DESC
                        LIMIT 200
                    ) recent_security_events
                    GROUP BY value
                    """
                ).fetchall()
                product_rows = conn.execute(
                    """
                    SELECT COALESCE(json_extract(payload_json, '$.product'), 'unknown') AS value, COUNT(*) AS c
                    FROM (
                        SELECT payload_json
                        FROM security_events
                        ORDER BY id DESC
                        LIMIT 200
                    ) recent_security_events
                    GROUP BY value
                    """
                ).fetchall()
                severity_counts = {str(row["value"]): int(row["c"]) for row in severity_rows}
                product_counts = {str(row["value"]): int(row["c"]) for row in product_rows}
            except sqlite3.OperationalError:
                recent_payload_rows = conn.execute(
                    """
                    SELECT payload_json
                    FROM security_events
                    ORDER BY id DESC
                    LIMIT 200
                    """
                ).fetchall()
                severity_counts: dict[str, int] = {}
                product_counts: dict[str, int] = {}
                for row in recent_payload_rows:
                    payload = json.loads(row["payload_json"])
                    sev = str(payload.get("severity") or "unknown")
                    prod = str(payload.get("product") or "unknown")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    product_counts[prod] = product_counts.get(prod, 0) + 1
        recent_events = [
            {
                "id": row["id"],
                "event_id": row["event_id"],
                "source_key": row["source_key"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in recent_event_rows
        ]
        return {
            "total_events": total_events,
            "total_sources": total_sources,
            "open_incidents": open_incidents,
            "open_cases": open_cases,
            "recent_events": recent_events,
            "recent_sources": [dict(row) for row in source_rows],
            "severity_counts": severity_counts,
            "product_counts": product_counts,
        }

    def create_incident(
        self,
        *,
        incident_key: str,
        title: str,
        severity: str,
        summary: str,
        first_seen: str,
        last_seen: str,
        events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO incidents (incident_key, title, severity, status, summary, first_seen, last_seen, created_at, updated_at)
                VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)
                """,
                (incident_key, title, severity, summary, first_seen, last_seen, now, now),
            )
            incident_id = int(cursor.lastrowid)
            normalized_events = [
                (
                    str(event.get("event_id", "")),
                    str(event.get("source_key", "")),
                    self._dump_json(event),
                )
                for event in (events or [])
            ]
            if normalized_events:
                conn.executemany(
                    """
                    INSERT INTO incident_events (incident_id, event_id, source_key, payload_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (incident_id, event_id, source_key, payload_json, now)
                        for event_id, source_key, payload_json in normalized_events
                    ],
                )
                lookup_keys = list(
                    {(source_key, event_id) for event_id, source_key, _ in normalized_events if source_key and event_id}
                )
                security_event_ids = self._find_security_event_ids_conn(conn=conn, lookup_keys=lookup_keys)
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO event_incident_links (
                        incident_id, event_id, source_key, security_event_id, linked_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            incident_id,
                            event_id,
                            source_key,
                            security_event_ids.get((source_key, event_id)),
                            now,
                        )
                        for event_id, source_key, _ in normalized_events
                    ],
                )
        return self.get_incident(incident_id)

    def list_incidents(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, incident_key, title, severity, status, summary, first_seen, last_seen, created_at, updated_at
                FROM incidents
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """
                ,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_incident(self, incident_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, incident_key, title, severity, status, summary, first_seen, last_seen, created_at, updated_at
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()
            if row is None:
                raise KeyError(incident_id)
            event_rows = conn.execute(
                """
                SELECT id, event_id, source_key, payload_json, created_at
                FROM incident_events
                WHERE incident_id = ?
                ORDER BY id
                """,
                (incident_id,),
            ).fetchall()
        incident = dict(row)
        incident["events"] = [
            {
                "id": event_row["id"],
                "event_id": event_row["event_id"],
                "source_key": event_row["source_key"],
                "payload": json.loads(event_row["payload_json"]),
                "created_at": event_row["created_at"],
            }
            for event_row in event_rows
        ]
        return incident

    def create_case(self, *, incident_id: int | None, title: str, assignee: str, description: str) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO cases (incident_id, title, assignee, status, description, created_at, updated_at)
                VALUES (?, ?, ?, 'open', ?, ?, ?)
                """,
                (incident_id, title, assignee, description, now, now),
            )
        return self.get_case(int(cursor.lastrowid))

    def update_case(
        self,
        case_id: int,
        *,
        assignee: str | None = None,
        status: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        updates: list[str] = []
        params: list[Any] = []
        if assignee is not None:
            updates.append("assignee = ?")
            params.append(assignee)
        if status is not None:
            if status not in self.VALID_CASE_STATUSES:
                raise ValueError("invalid_case_status")
            updates.append("status = ?")
            params.append(status)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        updates.append("updated_at = ?")
        params.append(utc_now())
        params.append(case_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE cases SET {', '.join(updates)} WHERE id = ?", params)
        return self.get_case(case_id)

    def list_cases(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, incident_id, title, assignee, status, description, created_at, updated_at
                FROM cases
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """
                ,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_case(self, case_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, incident_id, title, assignee, status, description, created_at, updated_at
                FROM cases
                WHERE id = ?
                """,
                (case_id,),
            ).fetchone()
            if row is None:
                raise KeyError(case_id)
            comment_rows = conn.execute(
                """
                SELECT id, author, body, created_at
                FROM case_comments
                WHERE case_id = ?
                ORDER BY id
                """,
                (case_id,),
            ).fetchall()
        case = dict(row)
        case["comments"] = [dict(comment_row) for comment_row in comment_rows]
        return case

    def add_case_comment(self, *, case_id: int, author: str, body: str) -> dict[str, Any]:
        self._require_case_exists(case_id)
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO case_comments (case_id, author, body, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (case_id, author, body, now),
            )
            conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
        return {
            "id": int(cursor.lastrowid),
            "case_id": case_id,
            "author": author,
            "body": body,
            "created_at": now,
        }

    def create_action(
        self,
        *,
        incident_id: int | None,
        case_id: int | None,
        action_type: str,
        target: str,
        requested_by: str,
    ) -> dict[str, Any]:
        if incident_id is None and case_id is None:
            raise ValueError("incident_id_or_case_id_required")
        if incident_id is not None:
            self._require_incident_exists(incident_id)
        if case_id is not None:
            self._require_case_exists(case_id)
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO actions (incident_id, case_id, action_type, target, status, requested_by, result_message, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'requested', ?, '', ?, ?)
                """,
                (incident_id, case_id, action_type, target, requested_by, now, now),
            )
        return {
            "id": int(cursor.lastrowid),
            "incident_id": incident_id,
            "case_id": case_id,
            "action_type": action_type,
            "target": target,
            "status": "requested",
            "requested_by": requested_by,
            "result_message": "",
            "created_at": now,
            "updated_at": now,
        }

    def update_action(self, action_id: int, *, status: str, result_message: str | None = None) -> dict[str, Any]:
        if status not in self.VALID_ACTION_STATUSES:
            raise ValueError("invalid_action_status")
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE actions
                SET status = ?, result_message = COALESCE(?, result_message), updated_at = ?
                WHERE id = ?
                """,
                (status, result_message, now, action_id),
            )
        return self.get_action(action_id)

    def update_action_fast(self, action_id: int, *, status: str, result_message: str | None = None) -> None:
        if status not in self.VALID_ACTION_STATUSES:
            raise ValueError("invalid_action_status")
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE actions
                SET status = ?, result_message = COALESCE(?, result_message), updated_at = ?
                WHERE id = ?
                """,
                (status, result_message, now, action_id),
            )

    def list_actions(self, *, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = """
            SELECT id, incident_id, case_id, action_type, target, status, requested_by, result_message, created_at, updated_at
            FROM actions
        """
        params: list[Any] = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY updated_at DESC, id DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def get_action(self, action_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, incident_id, case_id, action_type, target, status, requested_by, result_message, created_at, updated_at
                FROM actions
                WHERE id = ?
                """,
                (action_id,),
            ).fetchone()
        if row is None:
            raise KeyError(action_id)
        return dict(row)

    def create_export_record(
        self,
        *,
        source_key: str,
        adapter_version: str,
        request_payload: dict[str, Any],
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO xdr_exports (
                    source_key, adapter_version, status, exported_count, failed_count, request_json, result_json, created_at, updated_at
                )
                VALUES (?, ?, 'running', 0, 0, ?, '{}', ?, ?)
                """,
                (source_key, adapter_version, self._dump_json(request_payload), now, now),
            )
        return self.get_export_record(int(cursor.lastrowid))

    def finish_export_record(
        self,
        export_id: int,
        *,
        status: str,
        exported_count: int,
        failed_count: int,
        result_payload: dict[str, Any],
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE xdr_exports
                SET status = ?, exported_count = ?, failed_count = ?, result_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, exported_count, failed_count, self._dump_json(result_payload), now, export_id),
            )
        return self.get_export_record(export_id)

    def get_export_record(self, export_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, source_key, adapter_version, status, exported_count, failed_count, request_json, result_json, created_at, updated_at
                FROM xdr_exports
                WHERE id = ?
                """,
                (export_id,),
            ).fetchone()
        if row is None:
            raise KeyError(export_id)
        return {
            "id": row["id"],
            "source_key": row["source_key"],
            "adapter_version": row["adapter_version"],
            "status": row["status"],
            "exported_count": row["exported_count"],
            "failed_count": row["failed_count"],
            "request": json.loads(row["request_json"] or "{}"),
            "result": json.loads(row["result_json"] or "{}"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_export_records(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, source_key, adapter_version, status, exported_count, failed_count, request_json, result_json, created_at, updated_at
                FROM xdr_exports
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "source_key": row["source_key"],
                "adapter_version": row["adapter_version"],
                "status": row["status"],
                "exported_count": row["exported_count"],
                "failed_count": row["failed_count"],
                "request": json.loads(row["request_json"] or "{}"),
                "result": json.loads(row["result_json"] or "{}"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def link_event_incident(self, *, incident_id: int, source_key: str, event_id: str) -> dict[str, Any]:
        now = utc_now()
        self._require_incident_exists(incident_id)
        with self.connect() as conn:
            security_event_id = self._find_security_event_id_conn(conn=conn, source_key=source_key, event_id=event_id)
            conn.execute(
                """
                INSERT OR IGNORE INTO event_incident_links (
                    incident_id, event_id, source_key, security_event_id, linked_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (incident_id, event_id, source_key, security_event_id, now),
            )
            row = conn.execute(
                """
                SELECT id, incident_id, event_id, source_key, security_event_id, linked_at
                FROM event_incident_links
                WHERE incident_id = ? AND source_key = ? AND event_id = ?
                """,
                (incident_id, source_key, event_id),
            ).fetchone()
        if row is None:
            raise KeyError(f"{incident_id}:{source_key}:{event_id}")
        return dict(row)

    def list_event_incident_links(
        self,
        *,
        incident_id: int | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT id, incident_id, event_id, source_key, security_event_id, linked_at
            FROM event_incident_links
        """
        params: list[Any] = []
        if incident_id is not None:
            sql += " WHERE incident_id = ?"
            params.append(incident_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def create_remote_action(
        self,
        *,
        source_key: str,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        requested_by: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO remote_actions (
                    source_key, action_type, target, payload_json, status, requested_by, result_summary, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'pending', ?, '', ?, ?)
                """,
                (
                    source_key,
                    action_type,
                    target,
                    self._dump_json(payload),
                    requested_by,
                    now,
                    now,
                ),
            )
        return self.get_remote_action(int(cursor.lastrowid))

    def list_remote_actions(
        self,
        *,
        source_key: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT id, source_key, action_type, target, payload_json, status, requested_by, result_summary, created_at, updated_at
            FROM remote_actions
        """
        params: list[Any] = []
        filters: list[str] = []
        if source_key:
            filters.append("source_key = ?")
            params.append(source_key)
        if status:
            filters.append("status = ?")
            params.append(status)
        if filters:
            sql += " WHERE " + " AND ".join(filters)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "id": row["id"],
                "source_key": row["source_key"],
                "action_type": row["action_type"],
                "target": row["target"],
                "payload": json.loads(row["payload_json"] or "{}"),
                "status": row["status"],
                "requested_by": row["requested_by"],
                "result_summary": row["result_summary"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def get_remote_action(self, remote_action_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, source_key, action_type, target, payload_json, status, requested_by, result_summary, created_at, updated_at
                FROM remote_actions
                WHERE id = ?
                """,
                (remote_action_id,),
            ).fetchone()
        if row is None:
            raise KeyError(remote_action_id)
        return {
            "id": row["id"],
            "source_key": row["source_key"],
            "action_type": row["action_type"],
            "target": row["target"],
            "payload": json.loads(row["payload_json"] or "{}"),
            "status": row["status"],
            "requested_by": row["requested_by"],
            "result_summary": row["result_summary"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def ack_remote_action(
        self,
        remote_action_id: int,
        *,
        status: str,
        result_summary: str,
    ) -> dict[str, Any]:
        if status not in self.VALID_REMOTE_ACTION_STATUSES:
            raise ValueError("invalid_remote_action_status")
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE remote_actions
                SET status = ?, result_summary = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, result_summary, now, remote_action_id),
            )
        return self.get_remote_action(remote_action_id)

    def record_source_heartbeat(
        self,
        *,
        source_key: str,
        product: str,
        health_status: str,
        metrics: dict[str, Any],
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO source_heartbeats (
                    source_key, product, health_status, metrics_json, last_seen, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (source_key, product, health_status, self._dump_json(metrics), now, now),
            )
        return {
            "source_key": source_key,
            "product": product,
            "health_status": health_status,
            "metrics": metrics,
            "last_seen": now,
        }

    def list_source_health(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT h.source_key, h.product, h.health_status, h.metrics_json, h.last_seen
                FROM source_heartbeats h
                INNER JOIN (
                    SELECT source_key, MAX(id) AS max_id
                    FROM source_heartbeats
                    GROUP BY source_key
                ) x ON x.max_id = h.id
                ORDER BY h.last_seen DESC
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [
            {
                "source_key": row["source_key"],
                "product": row["product"],
                "health_status": row["health_status"],
                "metrics": json.loads(row["metrics_json"] or "{}"),
                "last_seen": row["last_seen"],
            }
            for row in rows
        ]

    def create_dispatch_log(
        self,
        *,
        action_id: int,
        connector: str,
        outcome: str,
        dry_run: bool,
        http_status: int | None = None,
        response_body: str = "",
        error_message: str = "",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO action_dispatch_logs (
                    action_id, connector, outcome, dry_run, http_status, response_body, error_message, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    connector,
                    outcome,
                    1 if dry_run else 0,
                    http_status,
                    response_body,
                    error_message,
                    now,
                ),
            )
        return {
            "id": int(cursor.lastrowid),
            "action_id": action_id,
            "connector": connector,
            "outcome": outcome,
            "dry_run": bool(dry_run),
            "http_status": http_status,
            "response_body": response_body,
            "error_message": error_message,
            "created_at": now,
        }

    def create_dispatch_log_fast(
        self,
        *,
        action_id: int,
        connector: str,
        outcome: str,
        dry_run: bool,
        http_status: int | None = None,
        response_body: str = "",
        error_message: str = "",
    ) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO action_dispatch_logs (
                    action_id, connector, outcome, dry_run, http_status, response_body, error_message, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    connector,
                    outcome,
                    1 if dry_run else 0,
                    http_status,
                    response_body,
                    error_message,
                    now,
                ),
            )

    def list_dispatch_logs(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, action_id, connector, outcome, dry_run, http_status, response_body, error_message, created_at
                FROM action_dispatch_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "action_id": row["action_id"],
                "connector": row["connector"],
                "outcome": row["outcome"],
                "dry_run": bool(row["dry_run"]),
                "http_status": row["http_status"],
                "response_body": row["response_body"],
                "error_message": row["error_message"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def get_dispatch_log(self, dispatch_log_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, action_id, connector, outcome, dry_run, http_status, response_body, error_message, created_at
                FROM action_dispatch_logs
                WHERE id = ?
                """,
                (dispatch_log_id,),
            ).fetchone()
        if row is None:
            raise KeyError(dispatch_log_id)
        return {
            "id": row["id"],
            "action_id": row["action_id"],
            "connector": row["connector"],
            "outcome": row["outcome"],
            "dry_run": bool(row["dry_run"]),
            "http_status": row["http_status"],
            "response_body": row["response_body"],
            "error_message": row["error_message"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _row_to_source(row: sqlite3.Row) -> SourceRecord:
        return SourceRecord(
            source_key=row["source_key"],
            product=row["product"],
            display_name=row["display_name"],
            token=row["token"],
            status=row["status"],
            last_seen=row["last_seen"],
            trust_mode=row["trust_mode"] if row["trust_mode"] else "legacy",
            allow_event_ingest=bool(row["allow_event_ingest"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _find_security_event_id_conn(
        *,
        conn: sqlite3.Connection,
        source_key: str,
        event_id: str,
    ) -> int | None:
        if not source_key or not event_id:
            return None
        row = conn.execute(
            """
            SELECT id
            FROM security_events
            WHERE source_key = ? AND event_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (source_key, event_id),
        ).fetchone()
        if row is None:
            return None
        return int(row["id"])

    @staticmethod
    def _find_security_event_ids_conn(
        *,
        conn: sqlite3.Connection,
        lookup_keys: list[tuple[str, str]],
    ) -> dict[tuple[str, str], int]:
        if not lookup_keys:
            return {}
        results: dict[tuple[str, str], int] = {}
        chunk_size = 200
        for i in range(0, len(lookup_keys), chunk_size):
            chunk = lookup_keys[i : i + chunk_size]
            pair_placeholders = ",".join(["(?, ?)"] * len(chunk))
            params: list[str] = []
            for source_key, event_id in chunk:
                params.extend([source_key, event_id])
            rows = conn.execute(
                f"""
                SELECT source_key, event_id, id
                FROM security_events
                WHERE (source_key, event_id) IN ({pair_placeholders})
                """,
                params,
            ).fetchall()
            for row in rows:
                results[(str(row["source_key"]), str(row["event_id"]))] = int(row["id"])
        return results

    @staticmethod
    def _is_hash_value(value: str) -> bool:
        if len(value) != 64:
            return False
        for c in value:
            if c not in "0123456789abcdef":
                return False
        return True

    @staticmethod
    def _token_pepper() -> str:
        return os.getenv("XDR_SOURCE_TOKEN_PEPPER", "")

    def _hash_token(self, token: str) -> str:
        material = f"{self._token_pepper()}::{token}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _verify_token(self, *, stored: str, provided: str) -> bool:
        if self._is_hash_value(stored):
            return secrets.compare_digest(stored, self._hash_token(provided))
        return secrets.compare_digest(stored, provided)

    @staticmethod
    def _dump_json(payload: Any) -> str:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def _require_incident_exists(self, incident_id: int) -> None:
        with self.connect() as conn:
            row = conn.execute("SELECT 1 FROM incidents WHERE id = ? LIMIT 1", (incident_id,)).fetchone()
        if row is None:
            raise KeyError(incident_id)

    def _require_case_exists(self, case_id: int) -> None:
        with self.connect() as conn:
            row = conn.execute("SELECT 1 FROM cases WHERE id = ? LIMIT 1", (case_id,)).fetchone()
        if row is None:
            raise KeyError(case_id)
