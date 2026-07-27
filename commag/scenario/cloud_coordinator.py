"""Desktop / Cloud Encrypted Score Evaluator.

Receives TenSEAL CKKS encrypted feature bundle under evaluation_context,
performs GENUINE HOMOMORPHIC EVALUATION (weighted dot product) directly
over the ciphertext, and produces encrypted_safety_score[evaluation_context].

ARCHITECTURE:
The cloud coordinator possesses ONLY the evaluation context (no secret key).
It cannot decrypt features or results.
"""
from __future__ import annotations
import time
import tenseal as ts
from commag.scenario.edge_gateway import get_ckks_evaluation_context


def cloud_eval_encrypted_score(ckks_ciphertext_eval: dict) -> dict:
    """Evaluate homomorphic weighted safety score over evaluation context.
    
    Transforms ckks_ciphertext[evaluation_context] to encrypted_safety_score[evaluation_context].
    """
    if ckks_ciphertext_eval.get("domain") != "ckks_ciphertext[evaluation_context]":
        raise ValueError("Cloud evaluation requires ckks_ciphertext[evaluation_context] domain")

    enc_bytes = ckks_ciphertext_eval.get("ciphertext_bytes")
    if not enc_bytes:
        raise ValueError("Missing CKKS ciphertext bytes — cannot evaluate. FAIL-CLOSED.")

    ctx = get_ckks_evaluation_context()
    ckks_vec = ts.ckks_vector_from(ctx, enc_bytes)

    # Homomorphic dot product directly on encrypted vector
    weights = [0.60, 0.25, 0.15]
    enc_weighted_score = ckks_vec.dot(weights)
    eval_ciphertext_bytes = enc_weighted_score.serialize()

    return {
        "eval_ciphertext_bytes": eval_ciphertext_bytes,
        "domain": "encrypted_safety_score[evaluation_context]",
        "timestamp": time.time(),
    }
