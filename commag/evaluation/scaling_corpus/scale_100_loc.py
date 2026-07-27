from library import extract_feature, encrypt_edge, eval_score, decrypt_score, apply_policy, authenticate_msg, verify_freshness, actuate, destroy_buffer, cloud_transmit

def helper_func_0(buf, key):
    v_0 = extract_feature(buf)
    enc_0 = encrypt_edge(v_0)
    cloud_transmit(enc_0)
    return enc_0

def helper_func_1(buf, key):
    v_1 = extract_feature(buf)
    enc_1 = encrypt_edge(v_1)
    cloud_transmit(enc_1)
    return enc_1

def helper_func_2(buf, key):
    v_2 = extract_feature(buf)
    enc_2 = encrypt_edge(v_2)
    cloud_transmit(enc_2)
    return enc_2

def helper_func_3(buf, key):
    v_3 = extract_feature(buf)
    enc_3 = encrypt_edge(v_3)
    cloud_transmit(enc_3)
    return enc_3

def helper_func_4(buf, key):
    v_4 = extract_feature(buf)
    enc_4 = encrypt_edge(v_4)
    cloud_transmit(enc_4)
    return enc_4

def helper_func_5(buf, key):
    v_5 = extract_feature(buf)
    enc_5 = encrypt_edge(v_5)
    cloud_transmit(enc_5)
    return enc_5

def main_pipeline(raw_media, secret_key):
    res = raw_media
    res = helper_func_0(raw_media, secret_key)
    res = helper_func_1(raw_media, secret_key)
    res = helper_func_2(raw_media, secret_key)
    res = helper_func_3(raw_media, secret_key)
    res = helper_func_4(raw_media, secret_key)
    res = helper_func_5(raw_media, secret_key)
    destroy_buffer(raw_media)
    destroy_buffer(secret_key)