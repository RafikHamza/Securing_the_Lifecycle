# Revision Summary

- Removed the previous project name from the public paper and release paths; the implementation package is now `cpd_verifier`.
- Replaced simulated or contradictory hardware claims with a verified Raspberry Pi 4 evidence bundle containing 210 static-analysis measurements and matching source, verifier, collector, and contract hashes.
- Added retained runtime evidence for real TenSEAL CKKS and ML-KEM-1024 execution, including proof that the cloud evaluation context has no secret key and repeated normal/emergency outcomes.
- Kept Raspberry Pi static-verifier measurements separate from Windows real-cryptography validation and from limited ESP32-S3 characterization.
- Retained the seven curated static-analysis scenarios while describing their limited evidentiary scope.
- Reclassified the inspected development/diagnostic corpus as diagnostic rather than blind evaluation.
- Limited manuscript claims to the Python AST analyzer; native libclang is not required for the present paper.
- Rebuilt the manuscript tables and evidence narrative around traceable raw files and hashes.
