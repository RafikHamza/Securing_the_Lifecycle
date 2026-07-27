#!/usr/bin/env python3
"""Aggregate ESP32-S3 Serial Benchmark Log Across 200 Runs.

Calculates mean, std-dev, min, max, P95 for cycles and time (ms).
Saves results/esp32s3/esp32s3_stats_summary.json.
"""
from __future__ import annotations
import json
import math
import numpy as np
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOG_FILE = ROOT / "results" / "esp32s3" / "esp32s3_raw_200runs.log"
OUT_SUMMARY = ROOT / "results" / "esp32s3" / "esp32s3_stats_summary.json"


EXPECTED_RUNS = 200
META_FILE = ROOT / "results" / "esp32s3" / "esp32s3_collection_metadata.json"


def main() -> int:
    print("==========================================================================")
    print("ESP32-S3 SERIAL BENCHMARK STATISTICAL AGGREGATOR")
    print("==========================================================================")

    if not LOG_FILE.exists():
        print(f"FAIL-CLOSED: Raw log file {LOG_FILE} not found.")
        print("Run stream_esp32s3_200runs.py on physical hardware first.")
        return 1

    if not META_FILE.exists():
        print(f"FAIL-CLOSED: Collection metadata {META_FILE} not found.")
        print("The raw log must be accompanied by provenance metadata from the collector.")
        return 1

    # Verify provenance metadata
    meta = json.loads(META_FILE.read_text(encoding="utf-8"))
    if meta.get("valid_runs_captured", 0) < EXPECTED_RUNS:
        print(f"FAIL-CLOSED: Metadata reports only {meta.get('valid_runs_captured', 0)} runs "
              f"(need {EXPECTED_RUNS}).")
        return 1

    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    times_us = []
    cycles = []
    seen_run_ids = set()

    for line in lines:
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                if data.get("type") == "vh-mlkem-esp32s3-bench" and "vh_avg_time_us" in data:
                    run_id = data.get("run_id")
                    if run_id in seen_run_ids:
                        continue  # skip duplicates
                    seen_run_ids.add(run_id)
                    times_us.append(data["vh_avg_time_us"])
                    cycles.append(data["vh_avg_cycles"])
            except (json.JSONDecodeError, KeyError):
                pass

    if len(times_us) < EXPECTED_RUNS:
        print(f"FAIL-CLOSED: Only {len(times_us)} valid unique records found in log "
              f"(need exactly {EXPECTED_RUNS}).")
        return 1

    times_ms = [t / 1000.0 for t in times_us]

    mean_time_ms = float(np.mean(times_ms))
    std_time_ms = float(np.std(times_ms))
    min_time_ms = float(np.min(times_ms))
    max_time_ms = float(np.max(times_ms))
    p95_time_ms = float(np.percentile(times_ms, 95))

    mean_cycles = float(np.mean(cycles))
    std_cycles = float(np.std(cycles))

    stats = {
        "total_runs": len(times_ms),
        "cpu_mhz": 240,
        "mean_decaps_time_ms": round(mean_time_ms, 4),
        "std_decaps_time_ms": round(std_time_ms, 4),
        "min_decaps_time_ms": round(min_time_ms, 4),
        "max_decaps_time_ms": round(max_time_ms, 4),
        "p95_decaps_time_ms": round(p95_time_ms, 4),
        "mean_cycles": round(mean_cycles, 1),
        "std_cycles": round(std_cycles, 1),
    }

    OUT_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    OUT_SUMMARY.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    print(f"Successfully aggregated {len(times_ms)} runs:")
    print(f"- Mean Decapsulation Time: {stats['mean_decaps_time_ms']} ms (std-dev: +- {stats['std_decaps_time_ms']} ms)")
    print(f"- Mean Decapsulation Cycles: {stats['mean_cycles']} cycles @ 240 MHz")
    print(f"Summary written to: {OUT_SUMMARY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
