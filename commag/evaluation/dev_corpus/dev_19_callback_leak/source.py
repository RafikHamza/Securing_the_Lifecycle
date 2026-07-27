from library import cloud_transmit, destroy_buffer

def run(raw_media):
    cloud_transmit(raw_media)
    destroy_buffer(raw_media)
