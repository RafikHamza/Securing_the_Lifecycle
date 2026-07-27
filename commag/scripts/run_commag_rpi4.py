#!/usr/bin/env python3
"""CPDVerifier ComMag Benchmark Runner for Raspberry Pi 4 Gateway.

Measures static verifier latency, memory footprint, and exact scenario warning matching
on the target execution platform.
"""
from __future__ import annotations
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "commag"))

from commag.scripts.run_commag_required import (
    REQUIRED_SCENARIOS,
    run_verifier_case,
)

OUT_SUMMARY = ROOT / "results" / "rpi4" / "rpi4_summary.json"
OUT_CASES = ROOT / "results" / "rpi4" / "rpi4_security_cases.json"
OUT_LOG = ROOT / "results" / "rpi4" / "rpi4_run.log"


def main() -> int:
    print("==========================================================================")
    print("CPD_VERIFIER RASPBERRY PI 4 / PLATFORM BENCHMARK RUNNER")
    print("==========================================================================")

    current_platform = platform.platform()
    is_rpi4 = ("aarch64" in current_platform or "arm" in current_platform.lower() or os.path.exists("/proc/device-tree/model"))

    print(f"Platform: {current_platform}")
    print(f"Python Version: {platform.python_version()}")
    print(f"Target is RPi4: {is_rpi4}")

    log_lines = [
        f"Platform: {current_platform}",
        f"Python Version: {platform.python_version()}",
        f"Target is RPi4: {is_rpi4}",
    ]

    case_results = []
    total_time_ms = 0.0
    all_passed = True

    for name, script_path, contract_path, expected_warnings in REQUIRED_SCENARIOS:
        full_script = ROOT / script_path
        full_contract = ROOT / contract_path
        res = run_verifier_case(name, full_script, full_contract, expected_warnings)
        case_results.append(res)
        total_time_ms += res["time_ms"]
        status_str = "PASS" if res["passed"] else "FAIL"
        if not res["passed"]:
            all_passed = False
        msg = f"[{status_str}] {name}: Expected={expected_warnings}, Observed={res['observed_warnings']} ({res['time_ms']:.3f} ms)"
        print(msg)
        log_lines.append(msg)

    avg_time_ms = total_time_ms / max(1, len(case_results))

    summary = {
        "platform": current_platform,
        "python_version": platform.python_version(),
        "is_probable_rpi4": is_rpi4,
        "cases_total": len(case_results),
        "cases_passed": sum(1 for c in case_results if c["passed"]),
        "all_passed": all_passed,
        "average_static_check_ms": round(avg_time_ms, 3),
        "total_static_check_ms": round(total_time_ms, 3),
    }

    OUT_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    OUT_CASES.write_text(json.dumps(case_results, indent=2), encoding="utf-8")
    OUT_LOG.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    print("\n--------------------------------------------------------------------------")
    print(f"Execution Completed: {summary['cases_passed']}/{summary['cases_total']} cases passed.")
    print(f"Average Static Check Latency: {summary['average_static_check_ms']} ms")
    print(f"Summary written to: {OUT_SUMMARY}")
    print("--------------------------------------------------------------------------")

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
