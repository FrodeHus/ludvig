from typing import List
import yara
import os, glob


def load_yara_rules(
    namespaces: List[str] = ["secrets", "webshells", "sbom", "fileformats"],
    custom: str = None,
) -> yara.Rules:
    rule_path = os.path.dirname(__file__)
    sources = {}
    for ns in namespaces:
        ns_rule_path = os.path.join(rule_path, "yara", ns)
        rule_codes = []
        for rule_file in os.listdir(ns_rule_path):
            with open(os.path.join(ns_rule_path, rule_file), "r") as r:
                rule_code = r.read()
                rule_codes.append(rule_code)

        sources[ns] = "\r\n".join(rule_codes)
    if custom:
        custom_rules = __load_custom_rules(custom)
        sources["custom"] = "\r\n".join(custom_rules)

    rule = yara.compile(sources=sources)
    return rule


def __load_custom_rules(path: str):
    custom_rules = []
    for rule_file in glob.iglob(os.path.join(path, "**/*.yar"), recursive=True):
        with open(rule_file, "r") as f:
            rule_code = f.read()
            custom_rules.append(rule_code)
    return custom_rules
