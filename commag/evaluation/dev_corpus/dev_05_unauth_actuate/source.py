from library import actuate, destroy_buffer

def bypass_auth(cmd, raw_media):
    actuate(cmd)
    destroy_buffer(raw_media)
