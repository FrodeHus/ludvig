from ._common import BaseScanner
from ludvig.rules import load_yara_rules
from ludvig.rules import download_rules
from ludvig import current_config
import os
from knack.log import get_logger
from typing import IO, List
from ludvig.types import Finding, FindingSample, SecretFinding, Severity, YaraRuleMatch

logger = get_logger(__name__)


class SecretScanner(BaseScanner):
    def __init__(self, deobfuscated=False) -> None:
        super().__init__(deobfuscated)
        if not os.path.exists(current_config.compiled_rules):
            logger.info("no rules found - downloading defaults...")
            download_rules(current_config.rule_sources, current_config.config_path)

        yara_rules = load_yara_rules(current_config.compiled_rules)
        self.__yara_rules = yara_rules

    def scan_file_data(
        self, file_data: IO[bytes], file_name: str, severity_level: Severity, **kwargs
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
                if severity < severity_level:
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