#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
import sys

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from exkururuxdr.correlation import _cross_product_chain_correlate, event_from_dict


def _safe_div(num: float, den: float) -> float:
    if den <= 0:
        return 0.0
    return num / den


def _to_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _event_time(base: datetime, offset_sec: int) -> str:
    return (base + timedelta(seconds=offset_sec)).isoformat().replace("+00:00", "Z")


def _build_group_events(src_ip: str, *, attack: bool, seed: int, window_sec: int) -> list[dict]:
    rng = random.Random(seed)
    t0 = datetime(2026, 3, 19, 0, 0, 0, tzinfo=timezone.utc)
    rows: list[dict] = []
    if attack:
        rows.append(
            {
                "event_id": f"{src_ip}-ndr-1",
                "time": _event_time(t0, rng.randint(0, 40)),
                "product": "exkururuipros",
                "category": "network",
                "event_type": "FLOW_BEACONING",
                "severity": "high",
                "score": 80,
                "src_ip": src_ip,
                "dst_ip": "192.0.2.10",
                "labels": ["flow", "anomaly"],
            }
        )
        rows.append(
            {
                "event_id": f"{src_ip}-ndr-2",
                "time": _event_time(t0, rng.randint(20, 90)),
                "product": "exkururuipros",
                "category": "network",
                "event_type": "FLOW_PORT_SCAN",
                "severity": "high",
                "score": 78,
                "src_ip": src_ip,
                "dst_ip": "192.0.2.20",
                "labels": ["flow", "anomaly"],
            }
        )
        rows.append(
            {
                "event_id": f"{src_ip}-edr-1",
                "time": _event_time(t0, rng.randint(30, 110)),
                "product": "exkururuedr",
                "category": "process",
                "event_type": "SUSPICIOUS_PROCESS",
                "severity": "high",
                "score": 85,
                "src_ip": src_ip,
                "dst_ip": "192.0.2.30",
                "labels": ["powershell", "encoded-command"],
            }
        )
    else:
        mode = seed % 4
        if mode == 0:
            rows.append(
                {
                    "event_id": f"{src_ip}-ndr-only",
                    "time": _event_time(t0, rng.randint(0, 40)),
                    "product": "exkururuipros",
                    "category": "network",
                    "event_type": "FLOW_BEACONING",
                    "severity": "medium",
                    "score": 40,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.40",
                    "labels": ["flow"],
                }
            )
        elif mode == 1:
            rows.append(
                {
                    "event_id": f"{src_ip}-ndr-maint-1",
                    "time": _event_time(t0, rng.randint(0, 40)),
                    "product": "exkururuipros",
                    "category": "network",
                    "event_type": "FLOW_BEACONING",
                    "severity": "medium",
                    "score": 48,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.41",
                    "labels": ["beaconing", "health-check", "maintenance"],
                }
            )
            rows.append(
                {
                    "event_id": f"{src_ip}-edr-maint-1",
                    "time": _event_time(t0, window_sec + 120 + rng.randint(0, 40)),
                    "product": "exkururuedr",
                    "category": "process",
                    "event_type": "SUSPICIOUS_PROCESS",
                    "severity": "medium",
                    "score": 52,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.42",
                    "labels": ["powershell", "maintenance", "signed-script"],
                }
            )
        elif mode == 2:
            rows.append(
                {
                    "event_id": f"{src_ip}-edr-only",
                    "time": _event_time(t0, rng.randint(0, 40)),
                    "product": "exkururuedr",
                    "category": "process",
                    "event_type": "SUSPICIOUS_PROCESS",
                    "severity": "medium",
                    "score": 45,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.50",
                    "labels": ["powershell"],
                }
            )
        else:
            rows.append(
                {
                    "event_id": f"{src_ip}-ndr-far",
                    "time": _event_time(t0, 0),
                    "product": "exkururuipros",
                    "category": "network",
                    "event_type": "FLOW_PORT_SCAN",
                    "severity": "medium",
                    "score": 50,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.60",
                    "labels": ["flow", "anomaly"],
                }
            )
            rows.append(
                {
                    "event_id": f"{src_ip}-edr-far",
                    "time": _event_time(t0, window_sec + 900),
                    "product": "exkururuedr",
                    "category": "process",
                    "event_type": "SUSPICIOUS_PROCESS",
                    "severity": "high",
                    "score": 70,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.61",
                    "labels": ["powershell", "encoded-command", "maintenance"],
                }
            )
    return rows


def _build_dataset(seed: int, attack_groups: int, benign_groups: int) -> tuple[list[dict], set[str], set[str]]:
    random.Random(seed)  # deterministic marker
    rows: list[dict] = []
    attack_ips: set[str] = set()
    benign_ips: set[str] = set()
    window_sec = 300
    for i in range(max(1, attack_groups)):
        ip = f"198.51.100.{(i % 220) + 10}"
        attack_ips.add(ip)
        rows.extend(_build_group_events(ip, attack=True, seed=seed + i * 13 + 1, window_sec=window_sec))
    for i in range(max(1, benign_groups)):
        ip = f"203.0.113.{(i % 220) + 10}"
        benign_ips.add(ip)
        rows.extend(_build_group_events(ip, attack=False, seed=seed + i * 17 + 3, window_sec=window_sec))
    return rows, attack_ips, benign_ips


def _evaluate(rows: list[dict], attack_ips: set[str], benign_ips: set[str], *, window_sec: int) -> dict:
    events = [event_from_dict(item) for item in rows]
    started = time.perf_counter()
    incidents = _cross_product_chain_correlate(rows, events, window_sec=window_sec)
    elapsed = time.perf_counter() - started
    predicted_ips = {str((item.get("group") or {}).get("src_ip") or "") for item in incidents}
    predicted_ips.discard("")

    tp = len(predicted_ips & attack_ips)
    fn = len(attack_ips - predicted_ips)
    fp = len(predicted_ips & benign_ips)
    tn = len(benign_ips - predicted_ips)
    recall = _safe_div(tp, tp + fn)
    fpr = _safe_div(fp, fp + tn)
    precision = _safe_div(tp, tp + fp)

    return {
        "groups_total": len(attack_ips) + len(benign_ips),
        "groups_attack": len(attack_ips),
        "groups_benign": len(benign_ips),
        "incidents_detected": len(incidents),
        "predicted_attack_groups": len(predicted_ips),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall_detection_rate": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "elapsed_sec": round(elapsed, 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run XDR correlation quality gate on deterministic synthetic groups.")
    parser.add_argument("--seed", type=int, default=20260319)
    parser.add_argument("--attack-groups", type=int, default=120)
    parser.add_argument("--benign-groups", type=int, default=120)
    parser.add_argument("--window-sec", type=int, default=300)
    parser.add_argument("--recall-min", type=float, default=0.95)
    parser.add_argument("--fpr-max", type=float, default=0.02)
    parser.add_argument("--out", type=Path, default=Path("/tmp/quality_xdr_correlation.json"))
    args = parser.parse_args()

    rows, attack_ips, benign_ips = _build_dataset(
        seed=int(args.seed),
        attack_groups=int(args.attack_groups),
        benign_groups=int(args.benign_groups),
    )
    metrics = _evaluate(rows, attack_ips, benign_ips, window_sec=max(60, int(args.window_sec)))
    checks = [
        {
            "name": "recall_detection_rate",
            "actual": _to_float(metrics.get("recall_detection_rate"), 0.0),
            "op": ">=",
            "threshold": float(args.recall_min),
        },
        {
            "name": "false_positive_rate",
            "actual": _to_float(metrics.get("false_positive_rate"), 1.0),
            "op": "<=",
            "threshold": float(args.fpr_max),
        },
    ]
    failed: list[str] = []
    for check in checks:
        if check["op"] == ">=":
            check["pass"] = bool(check["actual"] >= check["threshold"])
        else:
            check["pass"] = bool(check["actual"] <= check["threshold"])
        if not check["pass"]:
            failed.append(check["name"])

    result = {
        "ok": not failed,
        "failed_checks": failed,
        "seed": int(args.seed),
        "dataset": {"attack_groups": int(args.attack_groups), "benign_groups": int(args.benign_groups)},
        "thresholds": {"recall_min": float(args.recall_min), "fpr_max": float(args.fpr_max), "window_sec": int(args.window_sec)},
        "metrics": metrics,
        "checks": checks,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
