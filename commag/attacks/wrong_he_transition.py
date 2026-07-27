"""Misuse Case 2: Wrong HE Domain Operation / Unencrypted Cloud Evaluation.

Passes unencrypted multimodal_feature_bundle directly to cloud_eval_encrypted_score
without calling ckks_encrypt_edge().
Contract Rule Broken: cloud_eval_encrypted_score expects domain ckks_ciphertext[evaluation_context].
Expected Warning Code: unauthorized-domain-transition
"""
from commag.scenario.edge_gateway import (
    extract_visual_feature,
    extract_audio_feature,
    extract_telemetry_feature,
    bundle_multimodal_features,
    destroy_sensitive_buffer,
)
from commag.scenario.cloud_coordinator import cloud_eval_encrypted_score

def execute_wrong_he_operation(raw_video, raw_audio, raw_telemetry):
    visual_feature = extract_visual_feature(raw_video)
    audio_feature = extract_audio_feature(raw_audio)
    telemetry_feature = extract_telemetry_feature(raw_telemetry)

    multimodal_feature_bundle = bundle_multimodal_features(visual_feature, audio_feature, telemetry_feature)

    # VIOLATION: Passing unencrypted feature bundle directly to cloud_eval_encrypted_score
    encrypted_eval = cloud_eval_encrypted_score(multimodal_feature_bundle)

    destroy_sensitive_buffer(raw_video)
    destroy_sensitive_buffer(raw_audio)

if __name__ == "__main__":
    execute_wrong_he_operation({"raw": 1}, {"raw": 2}, {"raw": 3})
