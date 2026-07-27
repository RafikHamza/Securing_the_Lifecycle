from library import extract_feature, encrypt_edge, eval_score, decrypt_score, apply_policy, authenticate_msg, verify_freshness, actuate, destroy_buffer, cloud_transmit

def pipeline(raw_media, secret_key):
    feat = extract_feature(raw_media)
    enc = encrypt_edge(feat)
    cloud_transmit(enc)
    enc_score = eval_score(enc)
    score = decrypt_score(enc_score)
    cmd = apply_policy(score)
    auth_cmd = authenticate_msg(cmd)
    fresh_cmd = verify_freshness(auth_cmd)
    actuate(fresh_cmd)
    destroy_buffer(raw_media)
    destroy_buffer(secret_key)
