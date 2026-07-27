from library import destroy_buffer, cloud_transmit

def double_use(raw_media):
    destroy_buffer(raw_media)
    cloud_transmit(raw_media)
