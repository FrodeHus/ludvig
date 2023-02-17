from ._common import BaseScanner
from ludvig.rules import load_yara_rules
from ludvig.rules import download_rules
from ludvig.config import Config
import os
from knack.log import get_logger
from typing import IO, List
from ludvig import Finding, FindingSample, Severity

logger = get_logger(__name__)


class SecretScanner(BaseScanner):
    def __init__(self, config: Config, deobfuscated=False) -> None:
        super().__init__(config, deobfuscated)
        if not os.path.exists(config.compiled_rules):
            logger.info("no rules found - downloading defaults...")
            download_rules(config)

        yara_rules = load_yara_rules(config.compiled_rules)
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
                finding = Finding.from_secret(match, samples, file_name, {**kwargs})
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

    def accepted_files(self) -> List[str]:
        return ["*"]
