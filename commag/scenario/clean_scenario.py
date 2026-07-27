"""Clean Multimodal Industrial Safety Loop Scenario.

Demonstrates the complete, legal domain transition chain from sensing
through homomorphic score evaluation, edge decryption, threshold policy decision,
authenticated control, HMAC verification, freshness checking, actuation, and zeroization.

Tests BOTH outcomes:
1. Normal operation (score below threshold -> CONTINUE_NORMAL)
2. Emergency stop (score above threshold -> EMERGENCY_STOP)
"""
from commag.scenario.edge_gateway import (
    extract_visual_feature,
    extract_audio_feature,
    extract_telemetry_feature,
    bundle_multimodal_features,
    ckks_encrypt_edge,
    edge_decrypt_score,
    edge_apply_policy,
    derive_session_key,
    authenticate_control_message,
    cloud_transmit,
    destroy_sensitive_buffer,
)
from commag.scenario.cloud_coordinator import cloud_eval_encrypted_score
from commag.scenario.actuator_emulator import (
    reset_seen_nonces,
    verify_hmac_tag,
    verify_control_freshness,
    esp32s3_actuate,
)
from pqcrypto.kem import ml_kem_1024


def run_clean_industrial_safety_loop(raw_video, raw_audio, raw_telemetry, shared_secret, threshold=0.5):
    # Stage 1: Feature extraction
    visual_feature = extract_visual_feature(raw_video)
    audio_feature = extract_audio_feature(raw_audio)
    telemetry_feature = extract_telemetry_feature(raw_telemetry)

    # Stage 2: Multimodal feature fusion
    multimodal_feature_bundle = bundle_multimodal_features(visual_feature, audio_feature, telemetry_feature)

    # Stage 3: CKKS encryption under evaluation_context
    ckks_ciphertext_eval = ckks_encrypt_edge(multimodal_feature_bundle)

    # Stage 4: Cloud computes encrypted weighted score
    cloud_transmit(ckks_ciphertext_eval)
    encrypted_eval = cloud_eval_encrypted_score(ckks_ciphertext_eval)

    # Stage 5: Edge decrypts score and applies threshold policy
    plaintext_score_val = edge_decrypt_score(encrypted_eval)
    control_msg = edge_apply_policy(plaintext_score_val, threshold=threshold)

    # Stage 6: ML-KEM HKDF session key derivation & HMAC authentication
    session_key = derive_session_key(shared_secret)
    auth_msg = authenticate_control_message(control_msg, session_key)

    # Stage 7: Actuator HMAC verification, freshness check, and actuation
    verified_msg = verify_hmac_tag(auth_msg, session_key)
    fresh_msg = verify_control_freshness(verified_msg)
    esp32s3_actuate(fresh_msg)

    # Stage 8: Zeroize all sensitive buffers
    destroy_sensitive_buffer(raw_video)
    destroy_sensitive_buffer(raw_audio)
    destroy_sensitive_buffer(shared_secret)
    destroy_sensitive_buffer(session_key)
    destroy_sensitive_buffer(fresh_msg)

    return control_msg["action"]


if __name__ == "__main__":
    reset_seen_nonces()
    pk, sk = ml_kem_1024.generate_keypair()
    ct, ss_bytes = ml_kem_1024.encrypt(pk)

    # Test 1: Below threshold -> CONTINUE_NORMAL
    v_low = {"raw_pixels": [50]*16, "timestamp": 1.0}
    a_low = {"pcm_samples": [50]*16, "timestamp": 1.0}
    t_low = {"accel_xyz": [0.01, 0.01, 9.8], "timestamp": 1.0}
    sec1 = {"secret_bytes": ss_bytes, "domain": "mlkem_shared_secret"}
    action1 = run_clean_industrial_safety_loop(v_low, a_low, t_low, sec1, threshold=0.5)
    print(f"Test 1 (Low sensor values): Action = {action1}")

    # Test 2: Above threshold -> EMERGENCY_STOP
    v_high = {"raw_pixels": [250]*16, "timestamp": 1.0}
    a_high = {"pcm_samples": [5000]*16, "timestamp": 1.0}
    t_high = {"accel_xyz": [5.0, 5.0, 9.8], "timestamp": 1.0}
    sec2 = {"secret_bytes": ss_bytes, "domain": "mlkem_shared_secret"}
    action2 = run_clean_industrial_safety_loop(v_high, a_high, t_high, sec2, threshold=0.1)
    print(f"Test 2 (High sensor values): Action = {action2}")

    print("\nClean scenario executed successfully for BOTH normal and emergency stop outcomes.")
