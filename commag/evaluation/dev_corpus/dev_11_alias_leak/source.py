from library import cloud_transmit, destroy_buffer

def alias_leak(raw_media):
    ref = raw_media
    cloud_transmit(ref)
    destroy_buffer(raw_media)
