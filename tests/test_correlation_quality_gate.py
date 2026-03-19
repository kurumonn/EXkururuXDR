from __future__ import annotations

from scripts.correlation_quality_gate import _build_dataset, _evaluate


def test_correlation_quality_gate_includes_hard_negative_benign_groups() -> None:
    rows, attack_ips, benign_ips = _build_dataset(seed=20260319, attack_groups=12, benign_groups=12)
    benign_group_rows = [row for row in rows if str(row.get("src_ip") or "").startswith("203.0.113.")]
    assert benign_group_rows, "expected benign groups in the correlation corpus"
    near_miss_rows = [
        row
        for row in benign_group_rows
        if any(token in " ".join(map(str, row.get("labels", []))).lower() for token in {"beaconing", "powershell", "encoded-command", "maintenance"})
    ]
    assert near_miss_rows, "expected hard-negative benign rows"

    metrics = _evaluate(rows, attack_ips, benign_ips, window_sec=300)
    assert metrics["false_positive_rate"] <= 0.02
