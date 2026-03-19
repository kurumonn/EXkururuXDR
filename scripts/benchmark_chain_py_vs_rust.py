#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PY_BENCH = ROOT / "scripts" / "benchmark_chain_python.py"
RUST_CRATE = ROOT / "rust_chain_bench"
RUST_BIN = RUST_CRATE / "target" / "release" / "rust_chain_bench"


def run_command(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)


def parse_time_v(stderr: str) -> dict[str, float]:
    def find(pattern: str) -> float:
        m = re.search(pattern, stderr)
        return float(m.group(1)) if m else 0.0

    max_rss_kb = find(r"Maximum resident set size \(kbytes\):\s*(\d+)")
    return {
        "max_rss_kb": max_rss_kb,
        "max_rss_mb": round(max_rss_kb / 1024.0, 3),
        "user_sec": find(r"User time \(seconds\):\s*([0-9.]+)"),
        "sys_sec": find(r"System time \(seconds\):\s*([0-9.]+)"),
        "cpu_percent": find(r"Percent of CPU this job got:\s*(\d+)"),
    }


def parse_json_stdout(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        text = line.strip()
        if text.startswith("{") and text.endswith("}"):
            return json.loads(text)
    raise RuntimeError("json payload not found")


def generate_input_lines(*, events: int, loops: int, window_sec: int) -> list[str]:
    base = datetime(2026, 3, 11, 0, 0, 0, tzinfo=timezone.utc)
    ndr_types = ["FLOW_EWMA_SPIKE", "FLOW_PORT_SCAN", "BEACONING", "SUSPICIOUS_OUTBOUND"]
    edr_types = ["SUSPICIOUS_PROCESS", "PERSISTENCE_REGISTRY_RUNKEY", "CREDENTIAL_DUMPING"]

    lines = [f"CONFIG|{loops}|{window_sec}"]
    for i in range(events):
        ts = base + timedelta(seconds=i % 900)
        ts_text = ts.isoformat().replace("+00:00", "Z")
        src_ip = f"10.0.{(i // 512) % 200}.{i % 250 + 1}"
        dst_ip = f"198.51.100.{(i % 200) + 1}"
        if i % 3 == 0:
            product = "exkururuipros"
            event_type = ndr_types[i % len(ndr_types)]
            labels = "flow,anomaly,ndr"
        elif i % 3 == 1:
            product = "exkururuedr"
            event_type = edr_types[i % len(edr_types)]
            labels = "powershell,edr,endpoint"
        else:
            product = "misc_sensor"
            event_type = "GENERIC_ALERT"
            labels = "generic"
        score = 50.0 + float((i * 11) % 50)
        lines.append(
            f"EVENT|evt-{i}|{ts_text}|{product}|{event_type}|{src_ip}|{dst_ip}|{score:.2f}|{labels}"
        )
    return lines


def run_python(input_path: Path) -> dict[str, Any]:
    proc = run_command(
        ["/usr/bin/time", "-v", "python3", str(PY_BENCH), str(input_path)],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"python bench failed\nstdout={proc.stdout}\nstderr={proc.stderr}")
    payload = parse_json_stdout(proc.stdout)
    payload["resource"] = parse_time_v(proc.stderr)
    return payload


def run_rust(input_path: Path) -> dict[str, Any]:
    build = run_command(["cargo", "build", "--release", "--quiet"], cwd=RUST_CRATE)
    if build.returncode != 0:
        raise RuntimeError(f"rust build failed\nstdout={build.stdout}\nstderr={build.stderr}")
    proc = run_command(
        ["/usr/bin/time", "-v", str(RUST_BIN), str(input_path)],
        cwd=RUST_CRATE,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"rust bench failed\nstdout={proc.stdout}\nstderr={proc.stderr}")
    payload = parse_json_stdout(proc.stdout)
    payload["resource"] = parse_time_v(proc.stderr)
    return payload


def ratio(numerator: float, denominator: float) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=150000)
    parser.add_argument("--loops", type=int, default=6)
    parser.add_argument("--window-sec", type=int, default=300)
    parser.add_argument("--out", type=Path, default=Path("/tmp/perf_xdr_chain_py_vs_rust.json"))
    args = parser.parse_args()

    lines = generate_input_lines(events=max(1, args.events), loops=max(1, args.loops), window_sec=max(30, args.window_sec))

    with NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as fp:
        temp_path = Path(fp.name)
        fp.write("\n".join(lines))

    try:
        py = run_python(temp_path)
        rs = run_rust(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)

    py_elapsed = float(py.get("elapsed_sec", 0.0))
    rs_elapsed = float(rs.get("elapsed_sec", 0.0))
    py_rss = float(py.get("resource", {}).get("max_rss_mb", 0.0))
    rs_rss = float(rs.get("resource", {}).get("max_rss_mb", 0.0))

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "workload": {"events": args.events, "loops": args.loops, "window_sec": args.window_sec},
        "python": py,
        "rust": rs,
        "comparison": {
            "speedup_rust_vs_python": ratio(py_elapsed, rs_elapsed),
            "rss_ratio_rust_vs_python": ratio(rs_rss, py_rss),
            "rss_reduction_percent": (1.0 - ratio(rs_rss, py_rss)) * 100.0 if py_rss > 0 else None,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result, indent=2)
    args.out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
