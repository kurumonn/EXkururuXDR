#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8810}"
HOST_PORT="${BASE_URL#http://}"
HOST="${HOST_PORT%%:*}"
PORT="${HOST_PORT##*:}"
LIMIT="${2:-20}"
if [ -z "${XDR_API_ADMIN_TOKEN:-}" ]; then
  echo "XDR_API_ADMIN_TOKEN is required" >&2
  exit 1
fi
ADMIN_TOKEN="${XDR_API_ADMIN_TOKEN}"

cd "$(dirname "$0")/.."

if [ ! -x "./.venv/bin/uvicorn" ]; then
  echo "uvicorn not found: ./.venv/bin/uvicorn" >&2
  exit 1
fi

LOG_FILE="/tmp/exkururuxdr_orch_uvicorn_${PORT}.log"
PID_FILE="/tmp/exkururuxdr_orch_uvicorn_${PORT}.pid"
STARTED_BY_SCRIPT="0"

cleanup() {
  if [ "${STARTED_BY_SCRIPT}" != "1" ]; then
    return
  fi
  if [ -f "${PID_FILE}" ]; then
    PID="$(cat "${PID_FILE}" || true)"
    if [ -n "${PID}" ] && kill -0 "${PID}" 2>/dev/null; then
      kill "${PID}" || true
      wait "${PID}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
  fi
}
trap cleanup EXIT

if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
  echo "API already running on ${HOST}:${PORT}; reusing existing process"
else
  echo "Starting API server on ${HOST}:${PORT} ..."
  nohup ./.venv/bin/uvicorn exkururuxdr.api:app --app-dir src --host "${HOST}" --port "${PORT}" >"${LOG_FILE}" 2>&1 &
  echo $! > "${PID_FILE}"
  STARTED_BY_SCRIPT="1"
fi

for _ in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    echo "API ready"
    break
  fi
  sleep 0.5
done

if ! curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
  echo "API did not start. Log:" >&2
  if [ -f "${LOG_FILE}" ]; then
    cat "${LOG_FILE}" >&2
  fi
  exit 1
fi

echo "[1/2] orchestrator dispatch (dry-run)"
echo "Seeding one requested action ..."
SEED_KEY="inc-orch-smoke-$(date +%s)"
INCIDENT_ID="$(
  curl -fsS -X POST "${BASE_URL}/api/v1/incidents" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"incident_key\":\"${SEED_KEY}\",\"title\":\"orchestrator smoke\",\"severity\":\"medium\",\"summary\":\"auto seed for orchestrator check\",\"first_seen\":\"2026-03-11T10:00:00Z\",\"last_seen\":\"2026-03-11T10:01:00Z\",\"events\":[]}" \
    | ./.venv/bin/python -c "import json,sys; print(json.load(sys.stdin)['id'])"
)"

CASE_ID="$(
  curl -fsS -X POST "${BASE_URL}/api/v1/cases" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"incident_id\":${INCIDENT_ID},\"title\":\"orchestrator case\",\"assignee\":\"smoke\",\"description\":\"auto\"}" \
    | ./.venv/bin/python -c "import json,sys; print(json.load(sys.stdin)['id'])"
)"

curl -fsS -X POST "${BASE_URL}/api/v1/actions" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"incident_id\":${INCIDENT_ID},\"case_id\":${CASE_ID},\"action_type\":\"host_isolate\",\"target\":\"host-smoke\",\"requested_by\":\"smoke\"}" \
  >/dev/null

echo "Dispatching requested actions ..."
curl -fsS -X POST "${BASE_URL}/api/v1/orchestrator/dispatch" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"limit\":${LIMIT},\"dry_run\":true}"
echo

echo "[2/2] dispatch logs"
curl -fsS "${BASE_URL}/api/v1/orchestrator/dispatch-logs?limit=${LIMIT}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
echo
echo "Orchestrator check completed"
