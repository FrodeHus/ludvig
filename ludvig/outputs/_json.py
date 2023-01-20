from typing import List
from ludvig.types import Finding

class JsonOutput:
    def __init__(self, findings : List[Finding], deobfuscated = False) -> None:
        self.findings = findings
        self.deobfuscated = deobfuscated
    
    def output(self):
        pass