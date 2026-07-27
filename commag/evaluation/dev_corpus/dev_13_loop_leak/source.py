from library import cloud_transmit, destroy_buffer

def loop_leak(raw_media):
    for i in range(3):
        cloud_transmit(raw_media)
    destroy_buffer(raw_media)
