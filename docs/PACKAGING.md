# exkururuXDR パッケージングガイド

## Python パッケージのビルド

```bash
cd /path/to/exkururuXDR
python3 -m pip install --upgrade build
python3 -m build
```

生成物:

- `dist/*.whl`
- `dist/*.tar.gz`

## リリース確認項目

1. 公開 README を確認する
2. スキーマ検証サンプルが通る
3. ライセンスファイルが存在する

公開前の確認では、`docs/README.md` の公開/非公開区分に従うこと。
