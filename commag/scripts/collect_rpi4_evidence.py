#!/usr/bin/env python3
"""Collect fail-closed Raspberry Pi 4 evidence for the CPD verifier.

This script evaluates the Python static verifier only. It does not execute
TenSEAL, ML-KEM, camera/audio acquisition, or ESP32-S3 actuation.

Run from the artifact root on a physical Raspberry Pi 4:
    PYTHONPATH=. python commag/scripts/collect_rpi4_evidence.py

Outputs a timestamped directory and ZIP under results/rpi4/.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cpd_verifier.contract import load_contract
from cpd_verifier.verifier import verify_file

RESULT_ROOT = ROOT / "results" / "rpi4"
CONTRACT = ROOT / "commag" / "contracts" / "industrial_safety.contract.json"
VERIFIER = ROOT / "cpd_verifier" / "verifier.py"
REPEATS = 30
WARMUPS = 3

CASES = [
    ("clean_safety_loop", ROOT / "commag/scenario/clean_scenario.py", []),
    ("misuse_1_raw_media_leak", ROOT / "commag/attacks/raw_media_leak.py", ["forbidden-domain-sink"]),
    ("misuse_2_wrong_he_transition", ROOT / "commag/attacks/wrong_he_transition.py", ["unauthorized-domain-transition"]),
    ("misuse_3_shared_secret_send", ROOT / "commag/attacks/shared_secret_send.py", ["forbidden-domain-sink"]),
    ("misuse_4_unauthenticated_control", ROOT / "commag/attacks/unauthenticated_control.py", ["forbidden-domain-sink"]),
    ("misuse_5_replayed_control", ROOT / "commag/attacks/replayed_control.py", ["forbidden-domain-sink"]),
    ("misuse_6_post_destroy_use", ROOT / "commag/attacks/post_destroy_use.py", ["missing-zeroize", "unauthorized-domain-transition", "use-after-zeroize"]),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def percentile(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("empty values")
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def run_cmd(args: list[str]) -> str:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=20)
        return (proc.stdout or proc.stderr).strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def detect_pi4() -> dict:
    model = read_text(Path("/proc/device-tree/model")).replace("\x00", "")
    machine = platform.machine().lower()
    is_pi4 = "raspberry pi 4" in model.lower() and machine in {"aarch64", "arm64"}
    return {
        "model": model,
        "machine": machine,
        "is_raspberry_pi_4": is_pi4,
    }


def main() -> int:
    pi = detect_pi4()
    if not pi["is_raspberry_pi_4"]:
        print(json.dumps(pi, indent=2))
        raise SystemExit("FAIL-CLOSED: this script must run on a physical 64-bit Raspberry Pi 4")

    missing = [str(p) for p in [CONTRACT, VERIFIER, *(x[1] for x in CASES)] if not p.is_file()]
    if missing:
        raise SystemExit(f"FAIL-CLOSED: missing required files: {missing}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = RESULT_ROOT / f"rpi4_evidence_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=False)

    contract = load_contract(CONTRACT)
    raw_runs: list[dict] = []
    case_summaries: list[dict] = []

    for case_id, source, expected in CASES:
        expected_sorted = sorted(expected)
        for _ in range(WARMUPS):
            verify_file(contract, source)

        timings: list[float] = []
        observed_reference: list[str] | None = None
        for repeat in range(1, REPEATS + 1):
            start = time.perf_counter_ns()
            violations = verify_file(contract, source)
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000.0
            observed = sorted({v.code for v in violations})
            if observed != expected_sorted:
                raise SystemExit(
                    f"FAIL-CLOSED: {case_id} repeat {repeat} expected {expected_sorted}, observed {observed}"
                )
            if observed_reference is None:
                observed_reference = observed
            elif observed != observed_reference:
                raise SystemExit(f"FAIL-CLOSED: nondeterministic warnings for {case_id}")
            timings.append(elapsed_ms)
            raw_runs.append({
                "case_id": case_id,
                "repeat": repeat,
                "elapsed_ms": round(elapsed_ms, 6),
                "expected_warnings": expected_sorted,
                "observed_warnings": observed,
            })

        case_summaries.append({
            "case_id": case_id,
            "source": str(source.relative_to(ROOT)),
            "source_sha256": sha256(source),
            "repeats": REPEATS,
            "expected_warnings": expected_sorted,
            "observed_warnings": observed_reference or [],
            "mean_ms": round(statistics.fmean(timings), 6),
            "median_ms": round(statistics.median(timings), 6),
            "stdev_ms": round(statistics.stdev(timings), 6) if len(timings) > 1 else 0.0,
            "min_ms": round(min(timings), 6),
            "max_ms": round(max(timings), 6),
            "p95_ms": round(percentile(timings, 0.95), 6),
            "status": "PASS",
        })

    ru = resource.getrusage(resource.RUSAGE_SELF)
    # Linux reports ru_maxrss in KiB.
    peak_rss_mb = float(ru.ru_maxrss) / 1024.0

    environment = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "hostname_redacted": True,
        "raspberry_pi": pi,
        "uname": run_cmd(["uname", "-a"]),
        "os_release": read_text(Path("/etc/os-release")),
        "cpu_info": run_cmd(["lscpu"]),
        "memory_info": run_cmd(["free", "-h"]),
        "git_commit": run_cmd(["git", "rev-parse", "HEAD"]) if (ROOT / ".git").exists() else "not-a-git-checkout",
        "libclang_required_for_this_run": False,
        "analysis_scope": "Python AST verifier over seven ComMag scenario files",
    }

    hashes = {
        "collector_sha256": sha256(Path(__file__)),
        "verifier_sha256": sha256(VERIFIER),
        "contract_sha256": sha256(CONTRACT),
    }

    summary = {
        "status": "PASS",
        "physical_platform_verified": True,
        "scope": "Python static verifier only",
        "total_cases": len(CASES),
        "repeats_per_case": REPEATS,
        "total_measurements": len(raw_runs),
        "all_warning_sets_exact": True,
        "peak_rss_mb": round(peak_rss_mb, 3),
        "cases": case_summaries,
        "environment": environment,
        "hashes": hashes,
    }

    (out_dir / "rpi4_raw_runs.json").write_text(json.dumps(raw_runs, indent=2), encoding="utf-8")
    (out_dir / "rpi4_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "environment_manifest.txt").write_text(
        "\n\n".join(f"## {k}\n{v}" for k, v in environment.items()), encoding="utf-8"
    )

    zip_path = RESULT_ROOT / f"rpi4_evidence_{stamp}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(out_dir.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(out_dir))

    print(json.dumps({
        "status": "PASS",
        "evidence_directory": str(out_dir),
        "evidence_zip": str(zip_path),
        "evidence_zip_sha256": sha256(zip_path),
        "peak_rss_mb": round(peak_rss_mb, 3),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
