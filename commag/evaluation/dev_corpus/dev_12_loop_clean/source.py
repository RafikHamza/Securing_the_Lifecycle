from library import extract_feature, destroy_buffer

def loop_clean(raw_media):
    for i in range(3):
        feat = extract_feature(raw_media)
    destroy_buffer(raw_media)
    return feat
