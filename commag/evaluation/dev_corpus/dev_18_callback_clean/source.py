from library import extract_feature, destroy_buffer

def apply_cb(buf, cb):
    return cb(buf)

def run(raw_media):
    feat = apply_cb(raw_media, extract_feature)
    destroy_buffer(raw_media)
    return feat
