import json
from typing import List


class SecretScanRule:
    def __init__(self, name: str, pattern: str) -> None:
        self.name = name
        self.pattern = pattern

    def __str__(self):
        return json.dumps(dict(self), ensure_ascii=False)

    def to_json(self):
        return self.__str__()

    @staticmethod
    def from_json(values: dict):
        return SecretScanRule(values["name"], values["pattern"])
