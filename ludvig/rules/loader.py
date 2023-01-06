from typing import List
import yara
import os

def load_yara_rules(namespaces : List[str] = ["secrets"]) -> yara.Rules:
    rule_path = os.path.dirname(__file__)
    sources = {}
    for ns in namespaces:
        rule_path = os.path.join(rule_path, "yara", ns)
        rule_codes = []
        for rule_file in os.listdir(rule_path):
            with open(os.path.join(rule_path, rule_file), "r") as r:
                rule_code = r.read()
                rule_codes.append(rule_code)
            
        sources[ns] = "\r\n".join(rule_codes)
    rule = yara.compile(sources=sources)
    return rule