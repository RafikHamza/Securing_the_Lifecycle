from library import extract_feature, destroy_buffer

def sub_helper(buf):
    return extract_feature(buf)

def process(raw_media):
    feat = sub_helper(raw_media)
    destroy_buffer(raw_media)
    return feat
