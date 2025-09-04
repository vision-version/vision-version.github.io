import sys

import torch

sys.path.append("./")
from unixcoder import UniXcoder


class SimilarityService:
    def __init__(
        self,
        model_path="./model",
    ):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        if not torch.cuda.is_initialized():
            torch.cuda.init()
        self.model = UniXcoder(model_path)
        self.model.to(self.device)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    def encode_function(self, func):
        tokens_ids = self.model.tokenize([func], max_length=512, mode="<encoder-only>")
        source_ids = torch.tensor(tokens_ids).to(self.device)
        tokens_embeddings, func_embedding = self.model(source_ids)
        return func_embedding

    def calculate_similarity(self, string1, string2):
        embedding1 = self.encode_function(string1)
        embedding2 = self.encode_function(string2)

        norm_embedding1 = torch.nn.functional.normalize(embedding1, p=2, dim=1)
        norm_embedding2 = torch.nn.functional.normalize(embedding2, p=2, dim=1)

        similarity_cosine = torch.sum(norm_embedding1 * norm_embedding2, dim=1)
        return similarity_cosine.item()
