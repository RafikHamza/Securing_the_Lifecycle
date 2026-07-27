from library import extract_feature, destroy_buffer

class Processor:
    def __init__(self, raw):
        self.raw = raw
    def run(self):
        feat = extract_feature(self.raw)
        destroy_buffer(self.raw)
        return feat
