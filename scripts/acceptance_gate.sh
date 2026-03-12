#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8810}"
EVENTS="${2:-120}"

if [ -z "${XDR_API_ADMIN_TOKEN:-}" ]; then
  echo "XDR_API_ADMIN_TOKEN is required" >&2
  exit 1
fi

RESULT_JSON="$(cd "$(dirname "$0")/.." && PYTHONPATH=src ./.venv/bin/python scripts/benchmark_e2e.py "${BASE_URL}" "${EVENTS}")"
echo "${RESULT_JSON}"

MAX_P95_MS="${XDR_GATE_MAX_P95_MS:-250}"
MAX_LOSS_EVENTS="${XDR_GATE_MAX_LOSS_EVENTS:-0}"
MIN_INGEST_EPS="${XDR_GATE_MIN_INGEST_EPS:-20}"
MAX_BATCH_P95_MS="${XDR_GATE_MAX_BATCH_P95_MS:-50}"
MIN_BATCH_INGEST_EPS="${XDR_GATE_MIN_BATCH_INGEST_EPS:-200}"
MAX_DISPATCH_MS="${XDR_GATE_MAX_DISPATCH_MS:-400}"
MAX_RSS_MB="${XDR_GATE_MAX_RSS_MB:-220}"

python3 - <<'PY' "${RESULT_JSON}" "${MAX_P95_MS}" "${MAX_LOSS_EVENTS}" "${MIN_INGEST_EPS}" "${MAX_BATCH_P95_MS}" "${MIN_BATCH_INGEST_EPS}" "${MAX_DISPATCH_MS}" "${MAX_RSS_MB}"
import json
import sys

result = json.loads(sys.argv[1])
max_p95 = float(sys.argv[2])
max_loss = int(float(sys.argv[3]))
min_eps = float(sys.argv[4])
max_batch_p95 = float(sys.argv[5])
min_batch_eps = float(sys.argv[6])
max_dispatch = float(sys.argv[7])
max_rss = float(sys.argv[8])

checks = [
    ("loss_events", result["loss_events"] <= max_loss, f"{result['loss_events']} <= {max_loss}"),
    ("ingest_p95_ms", result["ingest_p95_ms"] <= max_p95, f"{result['ingest_p95_ms']} <= {max_p95}"),
    ("ingest_eps", result["ingest_eps"] >= min_eps, f"{result['ingest_eps']} >= {min_eps}"),
    ("ingest_batch_p95_ms", result["ingest_batch_p95_ms"] <= max_batch_p95, f"{result['ingest_batch_p95_ms']} <= {max_batch_p95}"),
    ("ingest_batch_eps", result["ingest_batch_eps"] >= min_batch_eps, f"{result['ingest_batch_eps']} >= {min_batch_eps}"),
    ("dispatch_ms", result["dispatch_ms"] <= max_dispatch, f"{result['dispatch_ms']} <= {max_dispatch}"),
]
if result.get("rss_mb", 0.0) > 0:
    checks.append(("rss_mb", result["rss_mb"] <= max_rss, f"{result['rss_mb']} <= {max_rss}"))

failed = [f"{name} ({detail})" for name, ok, detail in checks if not ok]
if failed:
    print("ACCEPTANCE_GATE=FAIL")
    for item in failed:
        print(f"- {item}")
    sys.exit(1)
print("ACCEPTANCE_GATE=PASS")
sys.exit(0)
PY
