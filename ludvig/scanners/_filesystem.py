from typing import List
import yara, os, glob
from ludvig.types import Finding, Severity
from ._common import BaseScanner


class FilesystemScanner(BaseScanner):
    def __init__(
        self,
        path: str,
        severity_level: Severity = Severity.MEDIUM,
        deobfuscated=False,
        custom_rules: str = None,
    ) -> None:
        super().__init__(deobfuscated, custom_rules)
        self.__path = path
        self.severity_level = severity_level
        self.findings: List[Finding] = []

    def scan(self):
        for filename in glob.iglob(os.path.join(self.__path, "**/*"), recursive=True):
            if os.path.isdir(filename):
                continue
            with open(filename, "rb") as f:
                finding = self.scan_file_data(f, filename)
                if finding:
                    self.findings.append(finding)
