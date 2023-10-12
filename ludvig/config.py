import json
import os
from dataclasses import dataclass, asdict


def get_config() -> "Config":
    return Config.load()


@dataclass
class VulnDbSource:
    name: str
    uri: str

    @property
    def __dict__(self):
        return asdict(self)


@dataclass
class RuleSetSource:
    name: str
    category: str
    url: str

    @property
    def __dict__(self):
        return asdict(self)


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
        self.latest_data_release = (
            "https://www.frodehus.dev/ludvig/ludvig_assets.tar.gz"
        )
        if rule_sources and "Built-in" not in rule_sources:
            rule_sources.append(
                RuleSetSource(
                    "Built-In",
                    "secrets",
                    "https://github.com/FrodeHus/ludvig-rules/archive/refs/tags/v0.0.2.tar.gz",
                )
            )
        else:
            rule_sources = [
                RuleSetSource(
                    "Built-In",
                    "secrets",
                    "https://github.com/FrodeHus/ludvig-rules/archive/refs/tags/v0.0.2.tar.gz",
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
