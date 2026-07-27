from library import actuate, destroy_buffer

def wrong_pass(score, raw_media):
    actuate(score)
    destroy_buffer(raw_media)
