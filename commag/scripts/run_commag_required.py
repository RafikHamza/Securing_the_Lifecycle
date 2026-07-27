#!/usr/bin/env python3
"""Run the seven curated embodied-IoT CPD static-analysis scenarios.

This runner records only observed static-verification results. It does not create
simulated sensing, cryptographic, network, or actuation latency values.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cpd_verifier.contract import load_contract
from cpd_verifier.verifier import verify_file

COMMAG_DIR = ROOT / "commag"
CONTRACT_PATH = COMMAG_DIR / "contracts" / "industrial_safety.contract.json"

CASES = [
    {
        "id": "clean_safety_loop",
        "description": "Clean Multimodal Industrial Safety Loop Pipeline",
        "source": "commag/scenario/clean_scenario.py",
        "expected_warnings": [],
    },
    {
        "id": "misuse_1_raw_media_leak",
        "description": "Raw video/audio media stream transmitted directly over network",
        "source": "commag/attacks/raw_media_leak.py",
        "expected_warnings": ["forbidden-domain-sink"],
    },
    {
        "id": "misuse_2_wrong_he_transition",
        "description": "Unencrypted feature bundle passed directly to cloud evaluator",
        "source": "commag/attacks/wrong_he_transition.py",
        "expected_warnings": ["unauthorized-domain-transition"],
    },
    {
        "id": "misuse_3_shared_secret_send",
        "description": "Direct network transmission of raw ML-KEM shared secret",
        "source": "commag/attacks/shared_secret_send.py",
        "expected_warnings": ["forbidden-domain-sink"],
    },
    {
        "id": "misuse_4_unauthenticated_control",
        "description": "Actuation control command executed without authentication verification",
        "source": "commag/attacks/unauthenticated_control.py",
        "expected_warnings": ["forbidden-domain-sink"],
    },
    {
        "id": "misuse_5_replayed_control",
        "description": "Actuation executed without checking freshness and replay",
        "source": "commag/attacks/replayed_control.py",
        "expected_warnings": ["forbidden-domain-sink"],
    },
    {
        "id": "misuse_6_post_destroy_use",
        "description": "Secret or session-key buffer accessed after destruction",
        "source": "commag/attacks/post_destroy_use.py",
        "expected_warnings": ["missing-zeroize", "unauthorized-domain-transition", "use-after-zeroize"],
    },
]


def main() -> int:
    print("=" * 74)
    print("COMMAG EMBODIED-IOT CURATED STATIC-VERIFICATION RUNNER")
    print("=" * 74)

    contract = load_contract(CONTRACT_PATH)
    results = []
    total_time_ms = 0.0

    for case in CASES:
        src_path = ROOT / case["source"]
        started = time.perf_counter_ns()
        violations = verify_file(contract, src_path)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        total_time_ms += elapsed_ms

        observed = sorted({v.code for v in violations})
        expected = sorted(case["expected_warnings"])
        passed = observed == expected
        record = {
            "id": case["id"],
            "description": case["description"],
            "contract": "commag/contracts/industrial_safety.contract.json",
            "source": case["source"],
            "expected_warnings": expected,
            "observed_warnings": observed,
            "status": "PASS" if passed else "FAIL",
            "violations_count": len(violations),
            "verification_time_ms": round(elapsed_ms, 6),
            "measurement_scope": "single local Python static-verifier execution",
        }
        results.append(record)
        print(f"[{record['status']}] {case['id']}: expected={expected}, observed={observed} ({elapsed_ms:.3f} ms)")

    out_dir = ROOT / "results" / "commag"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "security_cases.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    # Remove obsolete deterministic pipeline/resource files from older development builds.
    for obsolete in (out_dir / "latency.csv", out_dir / "resource_usage.csv"):
        if obsolete.exists():
            obsolete.unlink()

    passed_cases = sum(1 for r in results if r["status"] == "PASS")
    summary = {
        "mode": "curated_python_static_verification",
        "total_cases": len(results),
        "passed_cases": passed_cases,
        "all_warning_sets_exact": passed_cases == len(results),
        "total_local_verification_time_ms": round(total_time_ms, 6),
        "rpi4_physical_evidence_available": (ROOT / "results/rpi4/rpi4_summary.json").is_file(),
        "real_crypto_evidence_available": (out_dir / "real_crypto_validation.json").is_file(),
        "esp32s3_aggregate_timing_available": False,
        "evidence_files": [
            "results/commag/security_cases.json",
            "results/commag/real_crypto_validation.json",
            "results/rpi4/rpi4_summary.json",
            "results/rpi4/rpi4_raw_runs.json",
            "results/commag/scaling_benchmark.csv",
            "results/commag/evaluation_results.json",
        ],
        "scope_note": "Local timings are static source-verifier executions only. Physical Raspberry Pi and real-cryptography evidence are recorded separately.",
    }
    (out_dir / "commag_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("-" * 74)
    print(f"Curated verification completed: {passed_cases}/{len(results)} cases passed.")
    return 0 if passed_cases == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
