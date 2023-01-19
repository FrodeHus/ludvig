from typing import List
import yara, os, glob
from ludvig.types import Finding, FindingSample, SecretFinding, YaraRuleMatch


class FilesystemScanner:
    def __init__(self, path: str, rules: yara.Rules) -> None:
        self.__path = path
        self.__rules = rules
        self.findings: List[Finding] = []

    def scan(self):
        for filename in glob.iglob(os.path.join(self.__path, "**/*"), recursive=True):
            if os.path.isdir(filename):
                continue
            with open(filename, "rb") as f:
                try:
                    matches = self.__rules.match(data=f.read())
                    for match in matches:
                        samples = FindingSample.from_yara_match(match)
                        self.findings.append(
                            SecretFinding(YaraRuleMatch(match), samples, filename)
                        )
                except Exception as ex:
                    print(ex)
                    continue
                finally:
                    f.close()
