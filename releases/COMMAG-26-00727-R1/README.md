# Frozen R1 reproducibility artifact: COMMAG-26-00727

**Paper:** Securing the Lifecycle: Verifying Cryptographic Protection Domains in Multimodal Embodied IoT.

This is an **additive** release. The legacy CPD Verifier root files and pre-R1 snapshot are retained. The manuscript's Analyzer v2.1 evaluation is **not** represented by the old root README's 210 Raspberry Pi measurements.

**Publication state: staged, pending transfer of the exact frozen archive.** The expected archive is `COMMAG-26-00727_R1_REPRODUCIBILITY_ARTIFACT_FINAL.zip` (401,887 bytes, SHA-256 `17acb55c68536a279505b6fd0a19c1622c565ac2b302a6a3dbe8c4946e8c70b6`). The complete archive has 33 files (32 entries in the SHA-256 manifest). No original inputs or reference results should be changed.

## Reproduced evidence

- Held-out corpus: 37 projects (12 clean, 25 violating), with 27 expected warning instances.
- Warning-level accuracy: TP=26, FP=3, FN=1; precision 0.8966, recall 0.9630, F1 0.9286.
- Exact per-project agreement: 34/37; all 25 violating projects detected.
- Residual non-exact projects: C03, V22, V23.
- Reference Pi 4 campaign: 240 primary measurements and 1,110 held-out timing measurements.
- Real cryptography on Windows 11: 30 low-score + 30 high-score decisions, 60/60 expected actions; median 15.8702 ms and P95 18.2303 ms **steady-state computation only**; one-time CKKS context approximately 35.48 MB.
- The cloud CKKS context has no decryption secret; **honest cloud evaluation remains an assumption**. Network transmission and physical actuator execution were excluded from timing. No hard-real-time guarantee is claimed.

## Reproduction from the *complete, unchanged* archive

Verify the exact archive hash and internal manifest:

```bash
python releases/COMMAG-26-00727-R1/verify_frozen_archive.py /path/to/COMMAG-26-00727_R1_REPRODUCIBILITY_ARTIFACT_FINAL.zip
```

Then extract the frozen ZIP into a separate working directory, `cd` to its single top-level directory, and run:

```bash
python scripts/verify_package.py
python scripts/prepare_workspace.py
# Linux static/regression/held-out workflow (creates fresh virtual environment)
bash RUN_LINUX.sh
# On a physical 64-bit Raspberry Pi 4 with no power/thermal throttle:
bash RUN_RPI4.sh
# On a compatible x86-64 Linux host for real crypto (non-reference timing):
bash RUN_LINUX.sh --crypto
```

PowerShell on Windows with Python 3.13 x64 installed:

```powershell
powershell -ExecutionPolicy Bypass -File .\RUN_WINDOWS.ps1
# Static checks only:
powershell -ExecutionPolicy Bypass -File .\RUN_WINDOWS.ps1 -StaticOnly
```

The runner scripts use the versioned requirement files **inside the frozen ZIP**:
`requirements/static.txt`, `requirements/crypto-windows.txt`, `requirements/crypto-portable.txt`. A readable copy of their exact pins appears in this repository release directory. Do **not** substitute the old root `requirements.txt` for R1.

## Verification performed for staging

The frozen archive's manifest passed (32/32); preparation checked 208 analyzer and 226 corpus files. On a local Python 3.13 environment, the 37-case held-out reproduction reproduced the recorded metrics and 46 selected tests passed. The shell scripts passed `bash -n` and Python scripts passed compilation. **These checks do not constitute a full Windows cryptographic or physical Pi 4 rerun.**

## Preservation rule

The original root code, README, requirements, and older evidence are preserved. New R1 results should go into a **new versioned directory or release**, never replace the frozen ZIP or the legacy evidence. See `RELEASE_STATUS.md` for transfer and acceptance gates.
