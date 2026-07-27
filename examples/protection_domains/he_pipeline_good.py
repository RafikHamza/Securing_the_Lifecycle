def secure_inference(features, pk_A):
    ct = ckks_encrypt(features, pk_A)
    ct_sq = ckks_eval_mul(ct, ct)
    ct_out = ckks_bootstrap(ct_sq)
    store_ciphertext(ct_out)
    secure_zeroize(features)
