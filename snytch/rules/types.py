import json
from typing import List


class Rule:
    def __init__(self, name: str) -> None:
        self.name = name


class SecretScanRule(Rule):
    def __init__(self, name: str, pattern: str) -> None:
        super().__init__(name)
        self.pattern = pattern

    def __str__(self):
        return json.dumps(dict(self), ensure_ascii=False)

    def to_json(self):
        return self.__str__()

    @staticmethod
    def from_json(values: dict):
        return SecretScanRule(values["name"], values["pattern"])
