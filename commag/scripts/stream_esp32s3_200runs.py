#!/usr/bin/env python3
"""Stream Genuine Physical Serial Benchmark Runs from ESP32-S3 over COM8.

Connects to physical ESP32-S3 on COM8 at 115200 baud, captures raw benchmark runs,
and writes the raw log to results/esp32s3/esp32s3_raw_200runs.log.

FAIL-CLOSED DESIGN:
This script strictly requires an active physical serial connection on COM8.
- If the serial port cannot be opened, it fails immediately.
- If fewer than TARGET_RUNS (200) complete, valid, unique JSON records
  are captured, it fails immediately.
- It NEVER generates synthetic or fallback records.
- It validates required fields in each JSON record.
- It rejects duplicate run_id values.
- It writes provenance metadata alongside the raw log.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys
import time
from pathlib import Path
import serial

PORT = "COM8"
BAUD = 115200
TARGET_RUNS = 200
READ_TIMEOUT_SEC = 2.0
OVERALL_TIMEOUT_SEC = 300.0  # 5 minutes max collection window
ROOT = Path(__file__).resolve().parents[2]
OUT_LOG = ROOT / "results" / "esp32s3" / "esp32s3_raw_200runs.log"
OUT_META = ROOT / "results" / "esp32s3" / "esp32s3_collection_metadata.json"

REQUIRED_JSON_FIELDS = {
    "type", "vh_avg_cycles", "vh_avg_time_us", "run_id",
    "chip_model", "sdk_version", "build", "cpu_mhz",
    "run_total", "vh_ss_match",
}


def validate_record(data: dict) -> list[str]:
    """Return list of missing/invalid fields, empty if record is valid."""
    errors = []
    for field in REQUIRED_JSON_FIELDS:
        if field not in data:
            errors.append(f"missing field: {field}")
    if data.get("type") != "vh-mlkem-esp32s3-bench":
        errors.append(f"unexpected type: {data.get('type')}")
    if not data.get("vh_ss_match", False):
        errors.append("vh_ss_match is false (shared secret mismatch)")
    return errors


def main() -> int:
    print("=" * 74)
    print(f"STREAMING {TARGET_RUNS} GENUINE PHYSICAL SERIAL BENCHMARK RUNS FROM {PORT}")
    print("=" * 74)

    # --- Open physical serial port (fail closed) ---
    try:
        ser = serial.Serial(PORT, BAUD, timeout=READ_TIMEOUT_SEC)
        time.sleep(0.5)
        ser.reset_input_buffer()
        print(f"Opened physical serial port {PORT} at {BAUD} baud.")
    except Exception as exc:
        print(f"CRITICAL ERROR: Failed to open physical serial port {PORT}: {exc}")
        print("FAIL-CLOSED ENFORCED: Physical serial connection is required. Aborting.")
        return 1

    captured_lines: list[str] = []
    valid_records: list[dict] = []
    seen_run_ids: set[int] = set()
    rejected_records: list[dict] = []
    start_time = time.time()

    while len(valid_records) < TARGET_RUNS:
        elapsed = time.time() - start_time
        if elapsed > OVERALL_TIMEOUT_SEC:
            print(f"TIMEOUT after {elapsed:.1f}s with only {len(valid_records)}/{TARGET_RUNS} valid runs.")
            break

        line_bytes = ser.readline()
        if not line_bytes:
            continue

        line_str = line_bytes.decode("utf-8", errors="replace").strip()
        if not line_str:
            continue

        captured_lines.append(line_str)

        if not (line_str.startswith("{") and line_str.endswith("}")):
            continue

        try:
            data = json.loads(line_str)
        except json.JSONDecodeError:
            continue

        errors = validate_record(data)
        if errors:
            rejected_records.append({"run_id": data.get("run_id"), "errors": errors})
            continue

        run_id = data.get("run_id")
        if run_id in seen_run_ids:
            rejected_records.append({"run_id": run_id, "errors": ["duplicate run_id"]})
            continue

        seen_run_ids.add(run_id)
        valid_records.append(data)

        if len(valid_records) % 10 == 0 or len(valid_records) == 1:
            vh_us = data.get("vh_avg_time_us", 0.0)
            vh_cyc = data.get("vh_avg_cycles", 0)
            print(f"[{len(valid_records)}/{TARGET_RUNS}] Run {run_id}: "
                  f"cycles={vh_cyc}, time={vh_us} us")

    ser.close()
    end_time = time.time()

    # --- Strict validation: require exactly TARGET_RUNS ---
    if len(valid_records) < TARGET_RUNS:
        print(f"\nCRITICAL ERROR: Only {len(valid_records)}/{TARGET_RUNS} valid unique runs captured.")
        print("FAIL-CLOSED ENFORCED: Exactly 200 valid unique runs are required. Aborting.")
        if rejected_records:
            print(f"  ({len(rejected_records)} records were rejected during collection)")
        return 1

    # --- Write raw log ---
    OUT_LOG.parent.mkdir(parents=True, exist_ok=True)
    raw_text = "\n".join(captured_lines) + "\n"
    OUT_LOG.write_text(raw_text, encoding="utf-8")
    log_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    # --- Compute script hash for provenance ---
    script_path = Path(__file__).resolve()
    script_sha256 = hashlib.sha256(script_path.read_bytes()).hexdigest()

    # --- Extract board profile from first record ---
    first = valid_records[0]
    board_profile = {
        "chip_model": first.get("chip_model"),
        "chip_revision": first.get("chip_revision"),
        "flash_size_bytes": first.get("flash_size_bytes"),
        "sdk_version": first.get("sdk_version"),
        "cpu_mhz": first.get("cpu_mhz"),
        "build_timestamp": first.get("build"),
        "param_set": first.get("param_set"),
    }

    # --- Write provenance metadata ---
    metadata = {
        "collection_script": str(script_path),
        "collection_script_sha256": script_sha256,
        "serial_port": PORT,
        "baud_rate": BAUD,
        "target_runs": TARGET_RUNS,
        "valid_runs_captured": len(valid_records),
        "rejected_records": len(rejected_records),
        "total_raw_lines": len(captured_lines),
        "collection_start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
        "collection_end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time)),
        "collection_duration_sec": round(end_time - start_time, 2),
        "raw_log_path": str(OUT_LOG),
        "raw_log_sha256": log_sha256,
        "board_profile": board_profile,
    }
    OUT_META.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print(f"\nSuccessfully recorded {len(valid_records)} valid unique physical runs.")
    print(f"Raw log: {OUT_LOG}")
    print(f"Log SHA-256: {log_sha256}")
    print(f"Metadata: {OUT_META}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
