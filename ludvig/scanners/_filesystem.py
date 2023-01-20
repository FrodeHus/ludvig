from typing import List
import yara, os, glob
from ludvig.types import Finding, FindingSample, SecretFinding, Severity, YaraRuleMatch


class FilesystemScanner:
    def __init__(self, path: str, rules: yara.Rules, severity_level : Severity = Severity.MEDIUM) -> None:
        self.__path = path
        self.severity_level = severity_level
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
                        severity = Severity[match.meta["severity"]] if "severity" in match.meta else Severity.UNKNOWN
                        if severity < self.severity_level:
                            continue
                        samples = FindingSample.from_yara_match(match)
                        self.findings.append(
                            SecretFinding(YaraRuleMatch(match), samples, filename)
                        )
                except Exception as ex:
                    print(ex)
                    continue
                finally:
                    f.close()
