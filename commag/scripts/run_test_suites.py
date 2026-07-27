#!/usr/bin/env python3
"""Run and Log CPDVerifier Test Suites Separately.

Runs:
1. Core baseline test suite (excluding commag extension)
2. ComMag extension test suite
3. Combined test suite
Saves separate log files in results/commag/.
"""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "results" / "commag"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def run_pytest(cmd: list[str], log_file: Path) -> int:
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    log_content = f"Command: {' '.join(cmd)}\nExit Code: {res.returncode}\n\nSTDOUT:\n{res.stdout}\n\nSTDERR:\n{res.stderr}\n"
    log_file.write_text(log_content, encoding="utf-8")
    print(f"Logged to {log_file.name} (Exit code: {res.returncode})")
    return res.returncode


def main() -> int:
    print("==========================================================================")
    print("RUNNING CPD_VERIFIER SEPARATED TEST SUITES")
    print("==========================================================================")

    # 1. Baseline tests
    print("\n--- 1. Running Core Baseline Test Suite ---")
    cmd1 = [sys.executable, "-m", "pytest", "-v", "tests", "--ignore=tests/test_commag_scenarios.py"]
    rc1 = run_pytest(cmd1, OUT_DIR / "baseline_test.log")

    # 2. ComMag Extension tests
    print("\n--- 2. Running ComMag Extension Test Suite ---")
    cmd2 = [sys.executable, "-m", "pytest", "-v", "tests/test_commag_scenarios.py"]
    rc2 = run_pytest(cmd2, OUT_DIR / "commag_extension_test.log")

    # 3. Combined tests
    print("\n--- 3. Running Combined Test Suite ---")
    cmd3 = [sys.executable, "-m", "pytest", "-v", "tests"]
    rc3 = run_pytest(cmd3, OUT_DIR / "combined_test.log")

    print("\n--------------------------------------------------------------------------")
    print("Test Suites Completed. Log files generated in results/commag/")
    print("--------------------------------------------------------------------------")
    return 0 if (rc1 == 0 and rc2 == 0 and rc3 == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
