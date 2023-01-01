import re
from tarfile import TarFile
from typing import List

from ludvig.rules.types import Rule, SecretScanRule


class Layer:
    def __init__(self, id: str, created_by: str = None, empty_layer=False) -> None:
        self.id = id
        self.created_by = created_by
        self.empty_layer = empty_layer


class Image:
    def __init__(
        self, repo_tags: List[str], layers: List[Layer], image_archive: TarFile
    ) -> None:
        self.repo_tags = repo_tags
        self.layers = layers
        self.image_archive = image_archive

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.image_archive.close()


class Finding:
    def __init__(
        self, category: str, rule: Rule, filename: str, whiteout: bool = False
    ) -> None:
        self.category = category
        self.rule = rule
        self.filename = filename
        self.content = None
        self.whiteout = whiteout


class SecretFinding(Finding):
    def __init__(
        self, rule: SecretScanRule, secret_match: re.Match[str], filename: str
    ) -> None:
        super().__init__("Secret", rule, filename)
        content = secret_match.string
        matched = secret_match.group(len(secret_match.groups()))
        content = content.replace(matched, "*" * len(matched))
        self.content = content
