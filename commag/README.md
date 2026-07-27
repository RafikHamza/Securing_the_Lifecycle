# Multimodal Embodied-IoT CPD Scenario

This directory contains the Communications Magazine scenario used to explain and evaluate cryptographic protection-domain contracts.

## Workflow

1. raw visual, audio, and telemetry values remain local;
2. local features form a multimodal bundle;
3. the edge encrypts the bundle with CKKS;
4. the cloud evaluation context computes an encrypted score without a secret key;
5. the edge decrypts only the score and applies the policy threshold;
6. ML-KEM output is converted to an application key with HKDF;
7. the edge authenticates a canonical control object;
8. the actuator verifies authentication, expiry, nonce freshness, target, and versions before actuation;
9. sensitive buffers transition to `destroyed`.

## Evidence

- Seven curated static-analysis cases: `results/commag/security_cases.json`
- Real cryptography validation: `results/commag/real_crypto_validation.json`
- Raspberry Pi static-analysis evidence: `results/rpi4/`
- Scaling and diagnostic results: `results/commag/`

No aggregate ESP32-S3 performance claim is made.
