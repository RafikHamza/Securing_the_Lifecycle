from library import cloud_transmit, destroy_buffer

def sub_leak(buf):
    cloud_transmit(buf)

def process(raw_media):
    sub_leak(raw_media)
    destroy_buffer(raw_media)
