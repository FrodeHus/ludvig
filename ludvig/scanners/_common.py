from typing import IO, List
import os
from ludvig.rules import load_yara_rules
from ludvig.types import Finding, FindingSample, SecretFinding, Severity, YaraRuleMatch
from ludvig.rules import download_rules
from ludvig import current_config
from knack.log import get_logger

logger = get_logger(__name__)


class BaseScanner:
    def __init__(self, deobfuscated=False) -> None:
        self.deobfuscated = deobfuscated
        if not os.path.exists(current_config.compiled_rules):
            logger.info("no rules found - downloading defaults...")
            download_rules(current_config.rule_sources, current_config.config_path)

        yara_rules = load_yara_rules(current_config.compiled_rules)
        self.__yara_rules = yara_rules
        self.__findings: List[Finding] = []

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
                line = self.find_match_line_num(file_data, match)
                samples = FindingSample.from_yara_match(match, self.deobfuscated, line)
                finding = SecretFinding(
                    YaraRuleMatch(match), samples, file_name, **kwargs
                )
                findings.append(finding)
        except Exception as ex:
            return print(ex)
        finally:
            return findings

    def find_match_line_num(self, file_data, match):
        file_data.seek(0)
        fd = file_data.read(match.strings[0][0])
        line = fd.count(b"\n") + 1
        return line

    def register_findings(self, findings: List[Finding]):
        unique_hashes = {f.hash for f in self.findings}
        for finding in findings:
            if finding.hash in unique_hashes:
                continue
            self.__findings.append(finding)

    def get_unique_findings(self):
        unique_hashes = list({f.hash for f in self.__findings})
        unique_findings = []
        for finding in self.__findings:
            if finding.hash in unique_hashes:
                unique_findings.append(finding)
                unique_hashes.remove(finding.hash)

        return unique_findings
