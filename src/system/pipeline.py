class InferencePipeline:

    def __init__(self, extractor, predictor):

        self.extractor = extractor
        self.predictor = predictor

    def process_flow(self, flow):
        vector = self.extractor(flow)
        probability = self.predictor(vector)

        return flow.src_ip, probability

def dummy_extractor(flow):
    return flow.get_features()


def dummy_predictor(vector):
    return 0.95
        