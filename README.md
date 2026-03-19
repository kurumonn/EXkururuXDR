# exkururuXDR

[英語版 README](README.en.md)  
[4製品デモ概要](README.4stack.md)

EXkururuXDR は、隣接するセキュリティ製品から受けたイベントを相関し、インシデント、ケース、アクションへ落とし込む XDR コンポーネントです。  
この公開リポジトリでは、連携面、イベント契約、スキーマ、ローカル起動導線など、公開して評価価値の高い範囲を残しています。

この README は公開配布用の案内です。相関ロジックの核心や秘密情報は含めません。

## 公開範囲

- 共通イベント契約とスキーマ
- Source registry と ingest API
- Incident / Case / Action API
- 軽量な単体デプロイ導線
- 相関ルール形式のサンプル

相関重み付け、本番閾値、チューニング値、最適化の核心は公開版から除外しています。

## 公開しないもの

- 本番の admin token、source token、共有鍵、証明書、接続先 URL
- 相関重み付けの詳細、しきい値、チューニング値、最適化メモ
- private な runbook、内部 review 手順、顧客別の運用条件
- 実運用ログ、顧客データ、秘密コーパス、再現用内部ダンプ
- 非公開連携の URL / API / 認証情報

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
./.venv/bin/pytest -q
./.venv/bin/uvicorn exkururuxdr.api:app --app-dir src --reload --port 8810
```

Docker で起動する場合は `docker-compose.yaml` を使うと分かりやすいです。

```bash
cd /path/to/exkururuXDR
cp .env.example .env
docker compose -f docker-compose.yaml up --build
```

起動後は `http://127.0.0.1:8810` を開きます。

## 公開している環境変数

- `XDR_API_ADMIN_TOKEN`
- `XDR_SOURCE_TOKEN_PEPPER`
- `XDR_SOURCE_REQUIRE_NONCE` (既定: `1`)
- `XDR_SOURCE_REPLAY_TTL_SEC` (既定: `310`)
- `XDR_REPLAY_BACKEND` (`auto` / `redis` / `memory`, 既定: `auto`)
- `XDR_REDIS_URL` (`redis://...` を指定した場合に共有 replay cache を使用)
- `XDR_REPLAY_FALLBACK_TO_MEMORY` (既定: `1`)
- `XDR_REPLAY_CACHE_MAX_ITEMS` (既定: `200000`)

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

## signed_required ソース契約（v2）

`trust_mode=signed_required` の source は以下ヘッダーを要求します。

- `X-Source-Key`
- `X-Source-Token`
- `X-Source-Timestamp`
- `X-Source-Nonce`
- `X-Source-Signature`

署名文字列は `"{timestamp}.{nonce}.{raw_body}"` です。  
同一署名の短時間再送は replay として拒否します。
`XDR_REPLAY_BACKEND=redis` と `XDR_REDIS_URL` を設定すると、replay 判定は Redis 共有キャッシュに切り替わります。
Redis 障害時は `XDR_REPLAY_FALLBACK_TO_MEMORY=1` の場合にメモリ退避します。

## テスト

```bash
cd /path/to/exkururuXDR
PYTHONPATH=src ./.venv/bin/python -m pytest -q
```

品質ゲート（相関検知率/誤検知率）:

```bash
cd /path/to/exkururuXDR
python3 scripts/correlation_quality_gate.py --out /tmp/quality_xdr_correlation.json
```
