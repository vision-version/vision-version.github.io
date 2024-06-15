import torch
from unixcoder import UniXcoder

class SimilarityService:
    def __init__(self, model_path="./model"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = UniXcoder(model_path)
        self.model.to(self.device)

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
        return similarity_cosine.item()  # Assuming you want to return a scalar value

# Example usage
similarity_service = SimilarityService()

string1 = "return \"\'\" + path.replace(\"\'\", \"\'\\\"\'\\\"\'\") + \"\'\";"
string2 = "return StringUtils.escape( path );"

similarity_score = similarity_service.calculate_similarity(string1, string2)
print(f"Similarity Score: {similarity_score}")