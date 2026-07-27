from library import destroy_buffer, net_send

def bad_key_use(secret_key):
    destroy_buffer(secret_key)
    net_send(secret_key)
