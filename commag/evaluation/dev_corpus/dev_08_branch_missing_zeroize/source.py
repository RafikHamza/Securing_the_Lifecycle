from library import extract_feature, destroy_buffer

def conditional_zeroize(raw_media, flag):
    feat = extract_feature(raw_media)
    if flag:
        destroy_buffer(raw_media)
    else:
        pass
    return feat
