from typing import IO, List
from ludvig.rules.loader import load_yara_rules
from ludvig.types import Finding, FindingSample, SecretFinding, Severity, YaraRuleMatch


class BaseScanner:
    def __init__(self, deobfuscated=False, custom_rules: str = None) -> None:
        self.deobfuscated = deobfuscated
        yara_rules = load_yara_rules(custom=custom_rules)
        self.__yara_rules = yara_rules

    def scan_file_data(
        self, file_data: IO[bytes], file_name: str, **kwargs
    ) -> List[Finding]:
        findings = []
        try:
            matches = self.__yara_rules.match(data=file_data.read())
            for match in matches:

                severity = (
                    Severity[match.meta["severity"]]
                    if "severity" in match.meta
                    else Severity.UNKNOWN
                )
                if severity < self.severity_level:
                    continue
                if file_data.tell() < 1048576:
                    file_data.seek(0)
                    fd = file_data.read(match.strings[0][0])
                    line = fd.count(b"\n") + 1
                else:
                    line = -1
                samples = FindingSample.from_yara_match(match, self.deobfuscated, line)
                findings.append(
                    SecretFinding(YaraRuleMatch(match), samples, file_name, **kwargs)
                )
        except Exception as ex:
            return print(ex)
        finally:
            return findings
