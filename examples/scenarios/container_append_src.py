def process(key):
    items = []
    items.append(key)
    # key is never directly used after append; only items (the container) is passed to the forbidden sink
    unsafe_send(items)
    secure_zeroize(key)
