# Raspberry Pi 4 Static-Verification Evidence

This directory contains the retained physical Raspberry Pi 4 evidence captured on 2026-07-25.

- Platform: Raspberry Pi 4 Model B Rev. 1.5, aarch64
- Operating system: Debian GNU/Linux 13 (trixie)
- Scope: Python AST static verifier over seven curated ComMag scenario files
- Repetitions: 30 per case, 210 measurements total
- Warning-set result: exact expected match for every measurement

Files:

- `environment_manifest.txt`: platform and collection environment
- `rpi4_raw_runs.json`: all 210 raw timing and warning-set records
- `rpi4_summary.json`: per-case statistics, memory, hashes, and scope
- `rpi4_evidence_20260725T033126Z.zip`: original returned evidence archive

These values are static source-analysis times. They are not end-to-end sensing, encryption, network, cloud, or actuation latency.
