# CPD Verifier Artifact

CPD Verifier is a contract-guided Python analyzer for secret-lifecycle and cryptographic protection-domain violations. The ComMag extension checks a multimodal embodied-IoT safety workflow spanning raw sensing, local features, CKKS encrypted evaluation, ML-KEM key establishment, authenticated control, freshness checks, actuation, and destruction.

## Install and test

From the extracted artifact directory:

```bash
python -m venv .venv
```

Activate the environment using the command appropriate for your operating system, then run:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q tests
```

Expected retained suite result: **106 passed, 5 skipped**. The skipped checks require the optional native-C backend and are outside the manuscript's evaluation scope.

## Reproduce the curated ComMag cases

```bash
python commag/scripts/run_commag_required.py
```

Expected result: one clean case and six misuse cases match their exact expected warning sets.

## Inspect retained evidence

- `results/commag/security_cases.json`: curated case results
- `results/commag/real_crypto_validation.json`: real TenSEAL CKKS and ML-KEM-1024 validation
- `results/rpi4/rpi4_raw_runs.json`: 210 physical Raspberry Pi measurements
- `results/rpi4/rpi4_summary.json`: per-case statistics, memory, hashes, and scope
- `results/commag/scaling_benchmark.csv`: generated scaling fixtures
- `results/commag/evaluation_results.json`: development and diagnostic behavior
- `commag/docs/claim_evidence_matrix.md`: claim boundaries and evidence mapping

## Run real cryptography validation

With all dependencies installed:

```bash
python commag/scripts/run_real_crypto_validation.py
```

The runner fails closed if TenSEAL or ML-KEM is unavailable, if encapsulation and decapsulation disagree, if the cloud context contains a secret key, or if either policy outcome is incorrect.

## Collect a new Raspberry Pi 4 record

On a physical 64-bit Raspberry Pi 4:

```bash
python commag/scripts/collect_rpi4_evidence.py
```

The collector verifies the platform, runs 30 repetitions per case, checks exact warning sets, records raw timings and memory, and binds the evidence to source hashes.

## Scope

The manuscript evaluates the Python AST analyzer. Optional native-C/libclang functionality is included for engineering continuity but is not used as paper evidence. CPD verification does not prove cryptographic security, side-channel resistance, physical erasure, protocol liveness, or runtime integrity.
