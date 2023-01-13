from enum import Enum
import re
from tarfile import TarFile
from typing import List
import yara


class Layer:
    def __init__(self, id: str, created_by: str = None, empty_layer=False) -> None:
        self.id = id
        self.created_by = created_by
        self.empty_layer = empty_layer


class Image:
    def __init__(
        self,
        repo_tags: List[str],
        layers: List[Layer],
        environment: List[str],
        image_archive: TarFile,
    ) -> None:
        self.repo_tags = repo_tags
        self.layers = layers
        self.image_archive = image_archive
        self.environment = environment

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.image_archive.close()


class Severity(Enum):
    TRIVIAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class RuleMatch:
    def __init__(
        self,
        match: str,
        rule_name: str,
        severity: Severity = Severity.MEDIUM,
        category: str = None,
        tags: List[str] = None,
    ) -> None:
        self.match = match
        self.rule_name = rule_name
        self.severity = severity
        self.tags = tags
        self.category = category


class YaraRuleMatch(RuleMatch):
    def __init__(self, match: str, yara: yara.Match) -> None:
        super().__init__(
            match, yara.rule, yara.meta["severity"], yara.namespace, yara.tags
        )
        self.__yara_match = yara

    def strings(self) -> List[str]:
        strings = []
        for string_match in self.__yara_match.strings:
            strings.append(
                {
                    "offset": string_match[0],
                    "identifier": string_match[1],
                    "plaintext": string_match[2],
                }
            )
        return strings


class Finding:
    def __init__(
        self, category: str, match: RuleMatch, filename: str, whiteout: bool = False
    ) -> None:
        self.category = category
        self.match = match
        self.filename = filename
        self.content = None
        self.obfuscated_content = None
        self.whiteout = whiteout
        self.comment = None


class SecretFinding(Finding):
    def __init__(self, rule: RuleMatch, filename: str, layer: Layer = None) -> None:
        super().__init__(rule.category, rule, filename)
        strings = rule.strings()
        matched = strings[0]["plaintext"].decode("utf-8")
        location = strings[0]["offset"]
        obfuscation = "*" * len(matched)
        obfuscation = obfuscation[:7] + "..." if len(obfuscation) > 10 else obfuscation
        snippet = self.match.match.replace(matched, obfuscation)
        self.content = "{}: {}".format(location, self.match.match)
        self.obfuscated_content = "{}: {}".format(location, snippet)
        if layer:
            self.comment = "Created by: {}".format(
                layer.created_by[: layer.created_by.find("#")]
            )
