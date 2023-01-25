from enum import IntEnum
import json
from tarfile import TarFile
from typing import List
import yara


class Severity(IntEnum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class RuleMatch:
    def __init__(
        self,
        id: str,
        rule_name: str,
        severity: Severity = Severity.MEDIUM,
        category: str = None,
        description: str = None,
        tags: List[str] = None,
    ) -> None:
        self.id = id
        self.rule_name = rule_name
        self.severity = severity
        self.tags = tags
        self.category = category
        self.description = description


class YaraRuleMatch(RuleMatch):
    def __init__(self, yara: yara.Match) -> None:
        super().__init__(
            yara.meta["id"] if "id" in yara.meta else "LS00000",
            yara.rule,
            yara.meta["severity"] if "severity" in yara.meta else "UNKNOWN",
            yara.namespace,
            yara.meta["description"] if "description" in yara.meta else None,
            yara.tags,
        )


class FindingSample:
    def __init__(
        self, content: str, offset: int, deobfuscated=False, line_number: int = -1
    ) -> None:
        self.offset = offset
        self.line_number = line_number
        content = content[:10] + "..." if len(content) > 10 else content
        if deobfuscated:
            self.content = content
        else:
            obfuscated = "*" * len(content)
            self.content = (
                obfuscated[:10] + "..." if len(obfuscated) > 10 else obfuscated
            )

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)

    @classmethod
    def from_yara_match(
        cls, match: yara.Match, deobfuscated=False, line_number: int = -1
    ) -> List["FindingSample"]:
        samples = []
        for str_match in match.strings:
            offset = str_match[0]
            identifier = str_match[1]
            data = str_match[2]
            if data.isascii():
                data = data.decode("utf-8")
            else:
                data = "".join(format(x, "02x") for x in data)
            samples.append(FindingSample(data, offset, deobfuscated, line_number))
        return samples


class Finding:
    def __init__(
        self,
        category: str,
        match: RuleMatch,
        samples: List[FindingSample],
        filename: str,
    ) -> None:
        self.name = "{}/{}".format(category, match.rule_name)
        self.match = match
        self.filename = filename
        self.samples = samples
        self.severity = match.severity
        self.comment = None
        self.properties = {category: category}


class SecretFinding(Finding):
    def __init__(
        self,
        rule: RuleMatch,
        samples: List[FindingSample],
        filename: str,
        **kwargs,
    ) -> None:
        super().__init__(rule.category, rule, samples, filename)
        for arg in kwargs:
            self.properties[arg] = kwargs[arg]


class FindingEncoder(json.JSONEncoder):
    def default(self, o: Finding):
        return o.__dict__
