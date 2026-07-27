from library import net_send, destroy_buffer

def leak_score(score, raw_media):
    net_send(score)
    destroy_buffer(raw_media)
