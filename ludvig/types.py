from enum import Enum
import re
from tarfile import TarFile
from typing import IO, List
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
    UNKNOWN = 0
    TRIVIAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class RuleMatch:
    def __init__(
        self,
        rule_name: str,
        severity: Severity = Severity.MEDIUM,
        category: str = None,
        tags: List[str] = None,
    ) -> None:
        self.rule_name = rule_name
        self.severity = severity
        self.tags = tags
        self.category = category


class YaraRuleMatch(RuleMatch):
    def __init__(self, yara: yara.Match) -> None:
        super().__init__(
            yara.rule,
            yara.meta["severity"] if "severity" in yara.meta else "UNKNOWN",
            yara.namespace,
            yara.tags,
        )


class FindingSample:
    def __init__(self, content: str, offset : int) -> None:
        self.offset = offset
        self.content = content[:10] + "..." if len(content) > 10 else content
        obfuscated = "*" * len(content)
        self.obfuscated_content = obfuscated[:10] + "..." if len(obfuscated) > 10 else obfuscated

    @classmethod
    def from_yara_match(cls, match: yara.Match) -> List["FindingSample"]:
        samples = []
        for str_match in match.strings:
            offset = str_match[0]
            identifier = str_match[1]
            data = str_match[2]
            if data.isascii():
                data = data.decode("utf-8")
            else:
                data = "".join(format(x, "02x") for x in data)
            samples.append(FindingSample(data, offset))
        return samples


class Finding:
    def __init__(
        self,
        category: str,
        match: RuleMatch,
        samples: List[FindingSample],
        filename: str,
        whiteout: bool = False,
    ) -> None:
        self.category = category
        self.match = match
        self.filename = filename
        self.samples = samples
        self.whiteout = whiteout
        self.comment = None
        self.removed_by = None


class SecretFinding(Finding):
    def __init__(
        self,
        rule: RuleMatch,
        samples: List[FindingSample],
        filename: str,
        layer: Layer = None,
    ) -> None:
        super().__init__(rule.category, rule, samples, filename)
        if layer:
            self.comment = layer.created_by[: layer.created_by.find("#")]
