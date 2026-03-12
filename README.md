# exkururuXDR

[English README](README.en.md)
[4-stack demo note](README.4stack.md)

EXkururuXDR correlates events from adjacent security products and turns them into incidents, cases, and
actions. The public repository keeps the integration-facing surface, schema contracts, and local startup
path that are useful to evaluate openly.

## Public scope

- Common event contract and schema
- Source registry and ingest API
- Incident, case, and action API surface
- Lightweight standalone deployment
- Example correlation rule format

Correlation weighting, tuning logic, production acceptance thresholds, and detailed optimization notes are
intentionally excluded from the public distribution.

## Architecture role

```text
Product events
     |
     v
 EXkururuXDR
 correlation / incidenting
     |
     v
 downstream review and action
```

## Quick Start

```bash
cd /path/to/exkururuXDR
python3 -m venv .venv
./.venv/bin/pip install -U pip
./.venv/bin/pip install -e ".[dev]"
export XDR_API_ADMIN_TOKEN='replace-with-strong-random-token'
mkdir -p data
./.venv/bin/uvicorn exkururuxdr.api:app --app-dir src --reload --port 8810
```

## Public environment variables

- `XDR_API_ADMIN_TOKEN`
- `XDR_SOURCE_TOKEN_PEPPER`

## Public assets

- Contract: `docs/contracts/common_security_event_schema_v1.md`
- Schema: `docs/contracts/schemas/common_security_event_v1.schema.json`
- Example rules: `docs/correlation_rules/sample_rules.yml`

## API highlights

- `GET /healthz`
- `GET /dashboard`
- `POST /api/v1/sources`
- `POST /api/v1/events/single`
- `POST /api/v1/events/batch`
- `POST /api/v1/incidents`
- `POST /api/v1/cases`
- `POST /api/v1/actions`

## Testing

```bash
cd /path/to/exkururuXDR
PYTHONPATH=src ./.venv/bin/python -m pytest -q
```
