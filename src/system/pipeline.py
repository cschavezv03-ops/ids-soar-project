from src.intelligence.extractor import extract_features
from src.intelligence.flow_adapter import FlowAdapter

class InferencePipeline:

    def __init__(self, predictor):

        self.predictor = predictor

    def process_flow(self, flow):

        adapted_flow = FlowAdapter(flow)
        vector = extract_features(adapted_flow)
        probability = self.predictor(vector)

        return flow.src_ip, probability

def dummy_predictor(vector):
    return 0.95
        