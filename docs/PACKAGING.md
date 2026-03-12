# exkururuXDR Packaging Guide

## Build Python package

```bash
cd /path/to/exkururuXDR
python3 -m pip install --upgrade build
python3 -m build
```

Artifacts:

- `dist/*.whl`
- `dist/*.tar.gz`

## Release checklist

1. Public README reviewed.
2. Schema validation examples pass.
3. License file present.
