from library import cloud_transmit, destroy_buffer

def process_while_leak(raw_media):
    count = 0
    while count < 3:
        cloud_transmit(raw_media)
        count += 1
    destroy_buffer(raw_media)
