from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .storage import XdrStorage

_http_opener = urllib.request.build_opener(urllib.request.HTTPHandler, urllib.request.HTTPSHandler)


def _resolve_connector(action_type: str) -> str | None:
    value = action_type.lower()
    if "isolate" in value:
        return "edr"
    if "block" in value or "unblock" in value or "enforcement" in value or "waf" in value:
        return "ndr"
    return None


def _connector_url(connector: str) -> str:
    if connector == "edr":
        return os.getenv("XDR_EDR_URL", "").strip()
    if connector == "ndr":
        return os.getenv("XDR_NDR_URL", "").strip()
    return ""


def _dispatch_http(
    *,
    connector: str,
    action: dict[str, Any],
    token: str,
    timeout_sec: float,
) -> tuple[int, str]:
    url = _connector_url(connector)
    action_type = str(action.get("action_type") or "")
    target_raw = str(action.get("target") or "").strip()
    payload: dict[str, Any] = {
        "action_id": action["id"],
        "incident_id": action["incident_id"],
        "case_id": action["case_id"],
        "action_type": action_type,
        "target": action.get("target"),
        "requested_by": action["requested_by"],
        "requested_at": action["created_at"],
    }
    if connector == "ndr":
        action_type_lower = action_type.lower()
        if "unblock" in action_type_lower:
            payload["action_type"] = "unblock_ip"
            payload["target"] = {"ip": target_raw}
        elif "block" in action_type_lower:
            payload["action_type"] = "block_ip"
            payload["target"] = {"ip": target_raw}
        elif "enforcement" in action_type_lower or "waf" in action_type_lower:
            payload["action_type"] = "set_enforcement"
            payload["target"] = {"mode": target_raw or "block"}
        else:
            payload["target"] = {"value": target_raw}
        workspace = str(os.getenv("XDR_DEFAULT_WORKSPACE", "") or "").strip()
        if workspace:
            payload["workspace_slug"] = workspace
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _http_opener.open(req, timeout=timeout_sec) as response:
        response_body = response.read().decode("utf-8", errors="replace")
        return int(response.getcode()), response_body


def dispatch_requested_actions(
    *,
    storage: XdrStorage,
    limit: int = 20,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    if dry_run is None:
        dry_run = os.getenv("XDR_ORCHESTRATOR_DRY_RUN", "true").lower() in {"1", "true", "yes", "on"}
    timeout_sec = float(os.getenv("XDR_ORCHESTRATOR_TIMEOUT_SEC", "5"))
    token = os.getenv("XDR_ORCHESTRATOR_TOKEN", "").strip()
    actions = storage.list_actions(status="requested", limit=limit)
    report_items: list[dict[str, Any]] = []
    dispatched = 0
    failed = 0
    skipped = 0
    for action in actions:
        connector = _resolve_connector(str(action["action_type"]))
        if connector is None:
            skipped += 1
            message = "unsupported_action_type"
            storage.create_dispatch_log_fast(
                action_id=action["id"],
                connector="unknown",
                outcome="skipped",
                dry_run=dry_run,
                error_message=message,
            )
            report_items.append(
                {"action_id": action["id"], "connector": "unknown", "outcome": "skipped", "message": message}
            )
            continue

        if dry_run:
            dispatched += 1
            message = f"dry_run dispatched to {connector}"
            storage.update_action_fast(action["id"], status="completed", result_message=message)
            storage.create_dispatch_log_fast(
                action_id=action["id"],
                connector=connector,
                outcome="dispatched",
                dry_run=True,
                response_body=message,
            )
            report_items.append(
                {"action_id": action["id"], "connector": connector, "outcome": "dispatched", "message": message}
            )
            continue

        endpoint_url = _connector_url(connector)
        if not endpoint_url:
            failed += 1
            message = f"missing_connector_url:{connector}"
            storage.update_action_fast(action["id"], status="failed", result_message=message)
            storage.create_dispatch_log_fast(
                action_id=action["id"],
                connector=connector,
                outcome="failed",
                dry_run=False,
                error_message=message,
            )
            report_items.append({"action_id": action["id"], "connector": connector, "outcome": "failed", "message": message})
            continue

        try:
            status_code, response_body = _dispatch_http(
                connector=connector,
                action=action,
                token=token,
                timeout_sec=timeout_sec,
            )
            if 200 <= status_code < 300:
                dispatched += 1
                storage.update_action_fast(action["id"], status="completed", result_message=f"dispatched:{connector}")
                storage.create_dispatch_log_fast(
                    action_id=action["id"],
                    connector=connector,
                    outcome="dispatched",
                    dry_run=False,
                    http_status=status_code,
                    response_body=response_body[:2000],
                )
                report_items.append(
                    {
                        "action_id": action["id"],
                        "connector": connector,
                        "outcome": "dispatched",
                        "http_status": status_code,
                    }
                )
            else:
                failed += 1
                message = f"http_status:{status_code}"
                storage.update_action_fast(action["id"], status="failed", result_message=message)
                storage.create_dispatch_log_fast(
                    action_id=action["id"],
                    connector=connector,
                    outcome="failed",
                    dry_run=False,
                    http_status=status_code,
                    response_body=response_body[:2000],
                    error_message=message,
                )
                report_items.append(
                    {
                        "action_id": action["id"],
                        "connector": connector,
                        "outcome": "failed",
                        "http_status": status_code,
                        "message": message,
                    }
                )
        except urllib.error.URLError as exc:
            failed += 1
            message = str(exc.reason) if hasattr(exc, "reason") else str(exc)
            storage.update_action_fast(action["id"], status="failed", result_message=message[:200])
            storage.create_dispatch_log_fast(
                action_id=action["id"],
                connector=connector,
                outcome="failed",
                dry_run=False,
                error_message=message[:2000],
            )
            report_items.append(
                {"action_id": action["id"], "connector": connector, "outcome": "failed", "message": message}
            )
        except Exception as exc:  # defensive fallback
            failed += 1
            message = str(exc)
            storage.update_action_fast(action["id"], status="failed", result_message=message[:200])
            storage.create_dispatch_log_fast(
                action_id=action["id"],
                connector=connector,
                outcome="failed",
                dry_run=False,
                error_message=message[:2000],
            )
            report_items.append(
                {"action_id": action["id"], "connector": connector, "outcome": "failed", "message": message}
            )

    return {
        "total": len(actions),
        "dispatched": dispatched,
        "failed": failed,
        "skipped": skipped,
        "dry_run": dry_run,
        "items": report_items,
    }
