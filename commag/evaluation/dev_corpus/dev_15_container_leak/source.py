from library import cloud_transmit, destroy_buffer

def leak_container(raw_media):
    data = {"raw": raw_media}
    cloud_transmit(data["raw"])
    destroy_buffer(raw_media)
