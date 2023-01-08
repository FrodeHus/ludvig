from typing import List
import yara, os, glob
from ludvig.types import Finding, SecretFinding, YaraRuleMatch


class FilesystemScanner:
    def __init__(self, path: str, rules: yara.Rules) -> None:
        self.__path = path
        self.__rules = rules
        self.findings: List[Finding] = []

    def scan(self):
        for filename in glob.iglob(os.path.join(self.__path, "**/*"), recursive=True):
            if os.path.isdir(filename):
                continue
            with open(filename, "r") as f:
                try:
                    matches = self.__rules.match(data=f.read())
                    for match in matches:
                        offset = match.strings[0][0]
                        prefix_offset = 10 if offset > 10 else offset
                        offset = offset - prefix_offset
                        f.seek(offset)
                        snippet = f.read(len(match.strings[0][2]) + prefix_offset)
                        self.findings.append(
                            SecretFinding(YaraRuleMatch(snippet, match), filename)
                        )
                except:
                    continue
