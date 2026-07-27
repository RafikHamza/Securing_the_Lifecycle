from h1 import step1
from library import destroy_buffer

def run(raw_media):
    f = step1(raw_media)
    destroy_buffer(raw_media)
    return f
