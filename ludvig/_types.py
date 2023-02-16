from enum import IntEnum
import json
import os
from typing import List
import yara
from ludvig.rules import RuleSetSource
import hashlib
from dataclasses import dataclass, field, asdict
from ludvig.vulndb import Advisory, VulnDbSource


class ConfigEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, RuleSetSource):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)


class Config:
    def __init__(
        self,
        config_path: str,
        rule_sources: list[RuleSetSource] = None,
        vulndb_sources: list[VulnDbSource] = None,
    ) -> None:
        self.config_path = config_path
        self.compiled_rules = os.path.join(config_path, "ludvig.rules")
        self.config_file = os.path.join(config_path, "config.json")
        if rule_sources and "Built-in" not in rule_sources:
            rule_sources.append(
                RuleSetSource(
                    "Built-In",
                    "secrets",
                    "https://github.com/FrodeHus/ludvig-rules/archive/refs/tags/v0.0.1.tar.gz",
                )
            )
        else:
            rule_sources = [
                RuleSetSource(
                    "Built-In",
                    "secrets",
                    "https://github.com/FrodeHus/ludvig-rules/archive/refs/tags/v0.0.1.tar.gz",
                )
            ]

        self.rule_sources = rule_sources
        if not vulndb_sources:
            vulndb_sources = [
                VulnDbSource(
                    "GitHub Advisory",
                    "https://github.com/github/advisory-database/archive/refs/heads/main.zip",
                )
            ]
        self.vulndb_sources = vulndb_sources
        self.vuln_db_file = os.path.join(config_path, "ludvig.db")

    def save(self):
        with open(self.config_file, "w") as f:
            f.write(json.dumps(self.__dict__, indent=4, cls=ConfigEncoder))

    @staticmethod
    def load():
        config_path = os.path.join(os.path.expanduser("~"), ".ludvig")
        if not os.path.exists(config_path):
            os.makedirs(config_path)
        config_file = os.path.join(config_path, "config.json")
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                config = json.loads(f.read())
                return Config(
                    config["config_path"],
                    Config.parse_rule_sets(config["rule_sources"]),
                )

        return Config(config_path)

    @staticmethod
    def parse_rule_sets(d: dict):
        rules = []
        for rule_source in d:
            rules.append(
                RuleSetSource(
                    rule_source["name"], rule_source["category"], rule_source["url"]
                )
            )


class Severity(IntEnum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: Severity = field(default_factory=lambda: Severity.MEDIUM)
    category: str = field(default=None)
    description: str = field(default=None)
    tags: list[str] = field(default_factory=lambda: [])

    @property
    def __dict__(self):
        return asdict(self)

    @staticmethod
    def from_yara_match(yara: yara.Match) -> "RuleMatch":
        return RuleMatch(
            yara.meta["id"] if "id" in yara.meta else "LS00000",
            yara.rule,
            Severity[yara.meta["severity"]]
            if "severity" in yara.meta
            else Severity.UNKNOWN,
            yara.namespace,
            yara.meta["description"] if "description" in yara.meta else "",
            yara.tags,
        )

    def from_vuln_advisory(advisory: Advisory) -> "RuleMatch":
        return RuleMatch(
            advisory.id,
            advisory.ext_id,
            Severity.HIGH,
            advisory.ecosystem,
            advisory.details,
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
            data = str_match[2]
            if data.isascii():
                data = data.decode("utf-8")
            else:
                data = "".join(format(x, "02x") for x in data)
            samples.append(FindingSample(data, offset, deobfuscated, line_number))
        return samples


@dataclass
class Finding:
    id: str
    category: str
    rule: RuleMatch
    filename: str
    severity: Severity = field(init=False)
    samples: list[FindingSample] = field(default_factory=lambda: [])
    properties: dict = field(default_factory=dict)
    _hash: str = field(init=False, repr=False)

    def __post_init__(self):
        self.name = f"{self.category}/{self.rule.rule_name}"
        self.severity = self.rule.severity
        self.properties.update({"category": self.category})
        self._hash = hashlib.sha1(
            "|".join(
                [
                    self.name,
                    self.filename,
                    "@".join([s.content for s in self.samples]),
                ]
            ).encode()
        ).hexdigest()

    @property
    def __dict__(self):
        return asdict(self)

    @staticmethod
    def from_secret(
        yara_match: yara.Match,
        samples: list[FindingSample],
        file_name: str,
        meta: dict = {},
    ) -> "Finding":
        rule = RuleMatch.from_yara_match(yara_match)
        return Finding(rule.rule_id, rule.category, rule, file_name, samples, meta)

    @staticmethod
    def from_vuln_advisory(
        advisory: Advisory, actual_version: str, filename: str, meta: dict = {}
    ) -> "Finding":
        rule = RuleMatch.from_vuln_advisory(advisory)
        return Finding(
            advisory.id,
            "vulnerabilities",
            rule=rule,
            filename=advisory.package.name,
            properties=meta,
        )
