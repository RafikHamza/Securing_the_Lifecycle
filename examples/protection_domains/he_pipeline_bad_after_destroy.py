def pipeline(features):
    ct = ckks_encrypt(features)
    secure_zeroize(features)
    print(features)
    return ct
