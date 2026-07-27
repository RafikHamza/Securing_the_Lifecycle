from library import destroy_buffer

def alias_clean(raw_media):
    ref = raw_media
    destroy_buffer(ref)
