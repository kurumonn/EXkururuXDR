# exkururuXDR

[英語版 README](README.en.md)  
[4製品デモ概要](README.4stack.md)

EXkururuXDR は、隣接するセキュリティ製品から受けたイベントを相関し、インシデント、ケース、アクションへ落とし込む XDR コンポーネントです。  
この公開リポジトリでは、連携面、イベント契約、スキーマ、ローカル起動導線など、公開して評価価値の高い範囲を残しています。

## 公開範囲

- 共通イベント契約とスキーマ
- Source registry と ingest API
- Incident / Case / Action API
- 軽量な単体デプロイ導線
- 相関ルール形式のサンプル

相関重み付け、本番閾値、チューニング値、最適化の核心は公開版から除外しています。

## 役割

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

## クイックスタート

```bash
cd /path/to/exkururuXDR
python3 -m venv .venv
./.venv/bin/pip install -U pip
./.venv/bin/pip install -e ".[dev]"
export XDR_API_ADMIN_TOKEN='replace-with-strong-random-token'
mkdir -p data
./.venv/bin/uvicorn exkururuxdr.api:app --app-dir src --reload --port 8810
```

## 公開している環境変数

- `XDR_API_ADMIN_TOKEN`
- `XDR_SOURCE_TOKEN_PEPPER`

## 公開している主な資産

- 契約仕様: `docs/contracts/common_security_event_schema_v1.md`
- スキーマ: `docs/contracts/schemas/common_security_event_v1.schema.json`
- ルール例: `docs/correlation_rules/sample_rules.yml`

## 主な API

- `GET /healthz`
- `GET /dashboard`
- `POST /api/v1/sources`
- `POST /api/v1/events/single`
- `POST /api/v1/events/batch`
- `POST /api/v1/incidents`
- `POST /api/v1/cases`
- `POST /api/v1/actions`

## テスト

```bash
cd /path/to/exkururuXDR
PYTHONPATH=src ./.venv/bin/python -m pytest -q
```
