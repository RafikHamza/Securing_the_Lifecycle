from library import net_send, destroy_buffer

def leak_key(secret_key):
    net_send(secret_key)
    destroy_buffer(secret_key)
