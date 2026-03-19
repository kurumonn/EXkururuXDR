# exkururuXDR

[Japanese README](README.md)
[4-stack demo note](README.4stack.md)

EXkururuXDR correlates events from adjacent products into incidents, cases, and actions.
The public repository keeps the contracts, API surface, and local startup path that are useful to show
openly.

This README is for public distribution. It does not include secrets or private operational know-how.

## Public scope

- Common event schema and contracts
- Source registry and ingest API
- Incident, case, and action APIs
- Standalone local deployment
- Example rule format

Production correlation logic, tuning thresholds, and detailed optimization notes are intentionally excluded
from the public distribution.

## Not included in the public release

- Production admin tokens, source tokens, shared keys, certificates, and target URLs
- Correlation weights, thresholds, tuning values, and optimization notes
- Private runbooks, internal review procedures, and customer-specific operating rules
- Live operational logs, customer data, secret corpora, and internal dumps
- Non-public integration URLs, APIs, and credentials

## Tests

```bash
cd /path/to/exkururuXDR
python3 -m venv .venv
./.venv/bin/pip install -e ".[dev]"
./.venv/bin/pytest -q
```

Docker is the easiest way to run this package.

```bash
cd /path/to/exkururuXDR
cp .env.example .env
docker compose -f docker-compose.yaml up --build
```

Open `http://127.0.0.1:8810` after startup.

## Replay cache

- `XDR_SOURCE_REQUIRE_NONCE` (default: `1`)
- `XDR_SOURCE_REPLAY_TTL_SEC` (default: `310`)
- `XDR_REPLAY_BACKEND` (`auto` / `redis` / `memory`, default: `auto`)
- `XDR_REDIS_URL` (set this to enable the shared replay cache)
- `XDR_REPLAY_FALLBACK_TO_MEMORY` (default: `1`)
- `XDR_REPLAY_CACHE_MAX_ITEMS` (default: `200000`)

When `XDR_REPLAY_BACKEND=redis` and `XDR_REDIS_URL` are set, replay checks use Redis as a shared cache.
If Redis fails, the code falls back to in-memory replay tracking when `XDR_REPLAY_FALLBACK_TO_MEMORY=1`.
