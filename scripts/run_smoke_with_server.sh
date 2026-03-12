#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8810}"
HOST_PORT="${BASE_URL#http://}"
HOST="${HOST_PORT%%:*}"
PORT="${HOST_PORT##*:}"

cd "$(dirname "$0")/.."

if [ ! -x "./.venv/bin/uvicorn" ]; then
  echo "uvicorn not found: ./.venv/bin/uvicorn" >&2
  exit 1
fi

if [ ! -x "./.venv/bin/python" ]; then
  echo "python not found: ./.venv/bin/python" >&2
  exit 1
fi

if [ -z "${XDR_API_ADMIN_TOKEN:-}" ]; then
  echo "XDR_API_ADMIN_TOKEN is required" >&2
  exit 1
fi

LOG_FILE="/tmp/exkururuxdr_smoke_uvicorn_${PORT}.log"
PID_FILE="/tmp/exkururuxdr_smoke_uvicorn_${PORT}.pid"
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
  else
    echo "(no local startup log; API may be managed by another process)" >&2
  fi
  exit 1
fi

echo "Running smoke ..."
./.venv/bin/python scripts/smoke_api_py.py "${BASE_URL}"
echo "Smoke completed"
