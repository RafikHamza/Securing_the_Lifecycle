# External Evidence Integration Report

## Real cryptography validation

- Status: **PASS**
- Environment: Windows 11
- Runtime: Python 3.13.3
- TenSEAL: 0.3.16
- KEM: ML-KEM-1024
- Repetitions: 10 paired runs
- Outcomes: every repetition produced both `CONTINUE_NORMAL` and `EMERGENCY_STOP`
- Cloud evaluation context contains secret key: **false**
- Median time for the pair of complete outcomes: **1406.1185 ms**
- Mean time for the pair of complete outcomes: **1393.6910 ms**

The hashes recorded in `real_crypto_validation.json` match the release copies of:

- `commag/scenario/edge_gateway.py`
- `commag/scenario/cloud_coordinator.py`
- `commag/scenario/actuator_emulator.py`
- `commag/scenario/clean_scenario.py`
- `commag/scripts/run_real_crypto_validation.py`

The timing covers two complete scenario outcomes and must not be interpreted as isolated CKKS or ML-KEM latency.

## Raspberry Pi 4 static verification

- Status: **PASS**
- Physical platform verified: **true**
- Model: Raspberry Pi 4 Model B Rev. 1.5
- Architecture: aarch64
- Scope: Python static verifier only
- Cases: 7
- Repetitions per case: 30
- Measurements: 210
- Exact warning-set matches: 210/210
- Clean-case median: 19.396964 ms
- Clean-case P95: 20.270880 ms
- Misuse-case median range: 2.134699--6.631949 ms
- Peak RSS: 24.684 MB

The collector, verifier, contract, and seven scenario-source hashes recorded in `rpi4_summary.json` match the release files.

The original returned evidence ZIP has SHA-256:

`68bb266e4e874c4e37deb82e69d7db73be6b0034309b28e3f0b9d75f3a989a50`

The public extracted evidence redacts only the hostname from the `uname` text. Measurement values and hashes are unchanged.
