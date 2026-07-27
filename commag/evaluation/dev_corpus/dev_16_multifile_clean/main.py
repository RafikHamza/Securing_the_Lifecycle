from library import destroy_buffer
from helper import do_extract

def run(raw_media):
    feat = do_extract(raw_media)
    destroy_buffer(raw_media)
    return feat
