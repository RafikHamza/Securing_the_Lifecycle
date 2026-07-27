def wrong_domain_operation(features, pk_A):
    # ckks_eval_mul is defined only for ciphertext inputs. Passing raw features
    # is a domain error even though it looks like a normal function call.
    ct_bad = ckks_eval_mul(features, features)
    store_ciphertext(ct_bad)
    secure_zeroize(features)
