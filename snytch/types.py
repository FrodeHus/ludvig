from typing import List


class Layer:
    def __init__(self, id: str, created_by: str = None, empty_layer=False) -> None:
        self.id = id
        self.created_by = created_by
        self.empty_layer = empty_layer


class Image:
    def __init__(self, repo_tags: List[str], layers: List[Layer]) -> None:
        self.repo_tags = repo_tags
        self.layers = layers
