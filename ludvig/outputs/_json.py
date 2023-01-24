import json
from typing import List
from ludvig.types import Finding, FindingEncoder


class JsonOutput:
    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings

    def output(self):
        output = json.dumps(self.findings, indent=4, cls=FindingEncoder)
        print(output)
