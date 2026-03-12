# Common Security Event Schema v1

Updated: 2026-03-11  
Ticket: DEV-117

## 1. Purpose

Define a shared minimum event contract across:

- `EXkururuIPROS` (NDR/NIPS)
- `EXkururuEDR` (endpoint)
- `EXkururuXDR` (correlation/incident)

The goal is to preserve lightweight architecture while enabling cross-product correlation.

## 2. Design Principles

1. Keep payloads minimal.  
2. Prefer summary and metadata over raw logs.  
3. Send `raw_ref` for deep lookup instead of sending full raw content.  
4. Keep schema stable and additive (`schema_version` + optional extension fields).  

## 3. Required Fields

Required keys in every event:

- `schema_version`: must be `common_security_event_v1`
- `event_id`
- `time` (ISO8601)
- `product` (`exkururuipros|exkururuedr|exkururuxdr_import`)
- `category` (`network|process|file|persistence|identity|correlation`)
- `event_type`
- `severity` (`low|medium|high|critical`)
- `score` (0-100)
- `labels` (array)

Recommended keys:

- `asset_id`
- `hostname`
- `user`
- `src_ip`
- `dst_ip`
- `raw_ref`

## 4. JSON Schema Source

Canonical schema file:

- `docs/contracts/schemas/common_security_event_v1.schema.json`

Example payloads:

- `docs/contracts/schemas/examples/common_security_event_v1_ndr.json`
- `docs/contracts/schemas/examples/common_security_event_v1_edr.json`
- `docs/contracts/schemas/examples/common_security_event_v1_xdr_import.json`

## 5. Validation Rules

Baseline validation:

- required field presence
- fixed enum check (`product`, `category`, `severity`)
- `score` range check (`0 <= score <= 100`)
- type check (`labels` must be array)
- timestamp parse check for `time`
- IP format sanity check for `src_ip` / `dst_ip` when present

## 6. Extension Fields by Category

Examples:

- `network`: `dst_port`, `protocol`
- `process`: `process_name`, `parent_process_name`, `command_line`
- `file`: `file_path`, `file_hash`
- `persistence`: `target_path`, `autorun_key`
- `identity`: `principal_id`, `auth_method`
- `correlation`: `incident_id`, `correlation_rule_id`

Extensions must not break base schema compatibility.

## 7. Legacy Compatibility

`docs/ips/common_event_schema_v1.md` is IPS-internal focused.
`common_security_event_v1` is the cross-product shared contract.

Mapping rule:

- internal IPS events can be transformed into `common_security_event_v1`
- cross-product integration should always use `common_security_event_v1`

## 8. CLI Validation

Run validator:

```bash
cd /home/kurumonn/exkururuXDR
python scripts/validate_common_security_event_v1.py docs/contracts/schemas/examples/common_security_event_v1_ndr.json
```

Validate all examples:

```bash
python scripts/validate_common_security_event_v1.py \
  docs/contracts/schemas/examples/common_security_event_v1_ndr.json \
  docs/contracts/schemas/examples/common_security_event_v1_edr.json \
  docs/contracts/schemas/examples/common_security_event_v1_xdr_import.json
```

Exit code:

- `0`: all valid
- `1`: one or more invalid
