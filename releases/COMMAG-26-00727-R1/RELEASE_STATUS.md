# R1 staged release: acceptance record

Status: **INCOMPLETE: frozen binary archive not yet published through this repository**.

## Completed
- Old `main` snapshot archived at `archive/pre-r1-2026-10-13` (commit `c7a1f119b2c746b4847d31a20f57213c399b8275`).
- New additive branch `artifact/commag-26-00727-r1-frozen` created from the same exact commit.
- Original legacy repository paths have not been modified.
- Original final ZIP integrity verified: SHA-256 `17acb55c68536a279505b6fd0a19c1622c565ac2b302a6a3dbe8c4946e8c70b6`, internal 32/32 checks.
- Python workspace preparation verified 208 analyzer source files and 226 held-out corpus files.
- On local Python 3.13, 46 selected tests passed and the held-out 37-project exact evaluator reproduced TP=26 / FP=3 / FN=1, 34/37 exact.
- Static source checks: Python scripts compile; Linux and Pi shell drivers pass syntax checks.
- Separate R1 dependency-lock copies and verifier are staged.

## NOT completed
- Copy the **exact original** 401,887-byte frozen ZIP into `releases/COMMAG-26-00727-R1/`; do not rebuild it.
- Fetch the ZIP back from GitHub and rerun full SHA-256 and internal manifest validation.
- Run Windows TenSEAL + ML-KEM-1024 and physical Pi 4 reproduction (not available in the current Linux staging environment).
- Publish a final GitHub release/tag and review/merge only after the frozen binary is present.

Do not mark the R1 release as final or reproducible solely based on this documentation.
