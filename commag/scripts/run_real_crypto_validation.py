#!/usr/bin/env python3
"""Execute and record the real TenSEAL CKKS + ML-KEM control workflow.

Recommended platform: x86-64 Python 3.11 or 3.12 with dependencies installed.
This validation is intentionally separate from the Raspberry Pi static-verifier run.
"""
from __future__ import annotations

import hashlib
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import tenseal as ts
    from pqcrypto.kem import ml_kem_1024
except Exception as exc:
    raise SystemExit(f"FAIL-CLOSED: real crypto dependencies unavailable: {exc}")

from commag.scenario.actuator_emulator import reset_seen_nonces
from commag.scenario.clean_scenario import run_clean_industrial_safety_loop
from commag.scenario.edge_gateway import get_ckks_evaluation_context

OUT = ROOT / "results" / "commag" / "real_crypto_validation.json"
REPEATS = 10


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    # Validate that the cloud context cannot decrypt.
    eval_ctx = get_ckks_evaluation_context()
    has_secret = bool(eval_ctx.has_secret_key()) if hasattr(eval_ctx, "has_secret_key") else None
    if has_secret is True:
        raise SystemExit("FAIL-CLOSED: cloud evaluation context contains a secret key")

    timings = []
    outcomes = []
    for repeat in range(1, REPEATS + 1):
        pk, sk = ml_kem_1024.generate_keypair()
        ciphertext, shared_enc = ml_kem_1024.encrypt(pk)
        shared_dec = ml_kem_1024.decrypt(sk, ciphertext)
        if shared_enc != shared_dec:
            raise SystemExit(f"FAIL-CLOSED: ML-KEM shared-secret mismatch at repeat {repeat}")

        reset_seen_nonces()
        started = time.perf_counter_ns()
        low = run_clean_industrial_safety_loop(
            {"raw_pixels": [50] * 16, "timestamp": time.time()},
            {"pcm_samples": [50] * 16, "timestamp": time.time()},
            {"accel_xyz": [0.01, 0.01, 9.8], "timestamp": time.time()},
            {"secret_bytes": shared_dec, "domain": "mlkem_shared_secret"},
            threshold=0.5,
        )
        reset_seen_nonces()
        high = run_clean_industrial_safety_loop(
            {"raw_pixels": [250] * 16, "timestamp": time.time()},
            {"pcm_samples": [5000] * 16, "timestamp": time.time()},
            {"accel_xyz": [5.0, 5.0, 9.8], "timestamp": time.time()},
            {"secret_bytes": shared_dec, "domain": "mlkem_shared_secret"},
            threshold=0.1,
        )
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        if low != "CONTINUE_NORMAL" or high != "EMERGENCY_STOP":
            raise SystemExit(f"FAIL-CLOSED: incorrect policy outcomes: low={low}, high={high}")
        timings.append(elapsed_ms)
        outcomes.append({"repeat": repeat, "low": low, "high": high, "elapsed_ms": round(elapsed_ms, 6)})

    payload = {
        "status": "PASS",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "tenseal_version": getattr(ts, "__version__", "unknown"),
        "ml_kem_variant": "ML-KEM-1024",
        "cloud_context_has_secret_key": has_secret,
        "repeats": REPEATS,
        "mean_ms_for_two_complete_outcomes": round(statistics.fmean(timings), 6),
        "median_ms_for_two_complete_outcomes": round(statistics.median(timings), 6),
        "min_ms": round(min(timings), 6),
        "max_ms": round(max(timings), 6),
        "outcomes": outcomes,
        "source_hashes": {
            "edge_gateway.py": sha256(ROOT / "commag/scenario/edge_gateway.py"),
            "cloud_coordinator.py": sha256(ROOT / "commag/scenario/cloud_coordinator.py"),
            "actuator_emulator.py": sha256(ROOT / "commag/scenario/actuator_emulator.py"),
            "clean_scenario.py": sha256(ROOT / "commag/scenario/clean_scenario.py"),
            "validation_script": sha256(Path(__file__)),
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"status": "PASS", "output": str(OUT), "sha256": sha256(OUT)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
