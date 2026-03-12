#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8810}"
if [ -z "${XDR_API_ADMIN_TOKEN:-}" ]; then
  echo "XDR_API_ADMIN_TOKEN is required" >&2
  exit 1
fi
ADMIN_TOKEN="${XDR_API_ADMIN_TOKEN}"

echo "[1/7] healthz"
curl -fsS "${BASE_URL}/healthz" >/tmp/xdr_healthz.json
cat /tmp/xdr_healthz.json
echo

echo "[2/7] create source"
curl -fsS -X POST "${BASE_URL}/api/v1/sources" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "source_key": "smoke-edr-01",
    "product": "exkururuedr",
    "display_name": "Smoke EDR 01"
  }' >/tmp/xdr_source.json || true

# source_key conflict allowed in repeated runs: fetch existing token by list endpoint is intentionally not exposed.
if grep -q '"token"' /tmp/xdr_source.json; then
  SOURCE_TOKEN="$(python3 - <<'PY'
import json
print(json.load(open('/tmp/xdr_source.json', 'r', encoding='utf-8'))['token'])
PY
)"
else
  echo "source create conflict (expected on rerun). Recreate with random key..."
  RAND_KEY="smoke-edr-$(date +%s)"
  curl -fsS -X POST "${BASE_URL}/api/v1/sources" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"source_key\":\"${RAND_KEY}\",\"product\":\"exkururuedr\",\"display_name\":\"Smoke EDR ${RAND_KEY}\"}" \
    >/tmp/xdr_source.json
  SOURCE_TOKEN="$(python3 - <<'PY'
import json
print(json.load(open('/tmp/xdr_source.json', 'r', encoding='utf-8'))['token'])
PY
)"
  SOURCE_KEY="${RAND_KEY}"
fi

if [ -z "${SOURCE_KEY:-}" ]; then
  SOURCE_KEY="$(python3 - <<'PY'
import json
print(json.load(open('/tmp/xdr_source.json', 'r', encoding='utf-8'))['source_key'])
PY
)"
fi
echo "source_key=${SOURCE_KEY}"

echo "[3/7] ingest single"
curl -fsS -X POST "${BASE_URL}/api/v1/events/single" \
  -H "Content-Type: application/json" \
  -H "X-Source-Key: ${SOURCE_KEY}" \
  -H "X-Source-Token: ${SOURCE_TOKEN}" \
  -d '{
    "schema_version": "common_security_event_v1",
    "event_id": "smoke-evt-001",
    "time": "2026-03-11T10:00:00Z",
    "product": "exkururuedr",
    "category": "process",
    "event_type": "SUSPICIOUS_PROCESS",
    "severity": "high",
    "score": 87,
    "labels": ["powershell", "encoded-command"],
    "src_ip": "192.0.2.10",
    "dst_ip": null
  }' >/tmp/xdr_ingest_single.json
cat /tmp/xdr_ingest_single.json
echo

echo "[4/7] create incident"
INC_KEY="smoke-inc-$(date +%s)"
curl -fsS -X POST "${BASE_URL}/api/v1/incidents" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"incident_key\": \"${INC_KEY}\",
    \"title\": \"Smoke Incident\",
    \"severity\": \"high\",
    \"summary\": \"smoke run\",
    \"first_seen\": \"2026-03-11T10:00:00Z\",
    \"last_seen\": \"2026-03-11T10:04:00Z\",
    \"events\": [{\"event_id\": \"smoke-evt-001\", \"source_key\": \"${SOURCE_KEY}\"}]
  }" >/tmp/xdr_incident.json
INCIDENT_ID="$(python3 - <<'PY'
import json
print(json.load(open('/tmp/xdr_incident.json', 'r', encoding='utf-8'))['id'])
PY
)"
echo "incident_id=${INCIDENT_ID}"

echo "[5/7] create case"
curl -fsS -X POST "${BASE_URL}/api/v1/cases" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"incident_id\": ${INCIDENT_ID},
    \"title\": \"Smoke Case\",
    \"assignee\": \"smoke-user\",
    \"description\": \"smoke case\"
  }" >/tmp/xdr_case.json
CASE_ID="$(python3 - <<'PY'
import json
print(json.load(open('/tmp/xdr_case.json', 'r', encoding='utf-8'))['id'])
PY
)"
echo "case_id=${CASE_ID}"

echo "[6/7] create action"
curl -fsS -X POST "${BASE_URL}/api/v1/actions" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"incident_id\": ${INCIDENT_ID},
    \"case_id\": ${CASE_ID},
    \"action_type\": \"host_isolate\",
    \"target\": \"host-192-0-2-10\",
    \"requested_by\": \"smoke-user\"
  }" >/tmp/xdr_action.json
ACTION_ID="$(python3 - <<'PY'
import json
print(json.load(open('/tmp/xdr_action.json', 'r', encoding='utf-8'))['id'])
PY
)"
echo "action_id=${ACTION_ID}"

echo "[7/7] complete action"
curl -fsS -X PATCH "${BASE_URL}/api/v1/actions/${ACTION_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"status":"completed","result_message":"smoke completed"}' >/tmp/xdr_action_done.json
cat /tmp/xdr_action_done.json
echo

echo "SMOKE OK"
