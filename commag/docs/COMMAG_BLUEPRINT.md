# ComMag Paper and Artifact Blueprint

## Working title

**From Sensing to Actuation: Verifying Cryptographic Protection Domains in Multimodal Embodied IoT**

## Scenario

### Privacy-aware multimodal industrial-safety loop

- **ESP32-S3 endpoint:** environmental telemetry and actuator output.
- **Raspberry Pi 4 edge:** local feature extraction, multimodal fusion, static CPD verification, CKKS encryption, score decryption, policy application, and authenticated control.
- **Desktop/cloud coordinator:** evaluation-context CKKS weighted-score computation without a secret key.
- **Closed loop:** sensing -> local features -> encrypted evaluation -> local policy -> authenticated/fresh control -> actuation.

### Protection domains

`raw_video`, `raw_audio`, `raw_telemetry`, `visual_feature`, `audio_feature`, `telemetry_feature`, `multimodal_feature_bundle`, `ckks_ciphertext[evaluation_context]`, `encrypted_safety_score[evaluation_context]`, `local_plaintext_safety_score`, `mlkem_shared_secret`, `session_key`, `network_control`, `authenticated_control`, `fresh_control`, `destroyed`.

### Curated misuse cases

1. Raw video/audio leakage.
2. Plaintext input to encrypted evaluation.
3. Direct transmission of an ML-KEM shared secret.
4. Control-message authentication bypass.
5. Replay/freshness-check bypass.
6. Use after destruction.

## Claim boundaries

The verifier is static and pre-deployment. It checks whether Python source follows declared domain transitions, sink restrictions, authentication, freshness, and destruction APIs. It does not prove cryptographic primitives, detect physical attacks, replace protocol analysis, or provide runtime intrusion prevention.

Raspberry Pi measurements are static source-analysis times. Real cryptography validation is a separate Windows execution record. ESP32-S3 evidence is limited characterization with no aggregate timing claim.

## Visual elements

1. Device--edge--cloud architecture.
2. Authorized and forbidden protection-domain transitions.
3. Generated scaling-fixture timing curve.
4. Values and authorized domain transitions.
5. Curated cases with Raspberry Pi median and P95 analysis times.
6. Retained evidence and scope boundaries.
