def unsafe_downgrade(features, pk_A, sk_A):
    ct = ckks_encrypt(features, pk_A)
    recovered = ckks_decrypt_A(ct, sk_A)
    store_plaintext(recovered)
    secure_zeroize(features)
    secure_zeroize(recovered)
