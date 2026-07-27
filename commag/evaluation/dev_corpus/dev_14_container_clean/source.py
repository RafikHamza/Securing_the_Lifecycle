from library import extract_feature, destroy_buffer

def store_container(raw_media):
    data = {"raw": raw_media}
    feat = extract_feature(data["raw"])
    destroy_buffer(raw_media)
    return feat
