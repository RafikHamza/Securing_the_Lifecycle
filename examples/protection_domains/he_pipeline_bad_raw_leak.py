def insecure_logging(features, pk_A):
    print(features)
    ct = ckks_encrypt(features, pk_A)
    store_ciphertext(ct)
    secure_zeroize(features)
