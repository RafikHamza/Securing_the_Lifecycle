from library import extract_feature, destroy_buffer

def process_while(raw_media):
    count = 0
    while count < 3:
        feat = extract_feature(raw_media)
        count += 1
    destroy_buffer(raw_media)
    return feat
