from typing import List
import yara, os, glob
from ludvig.types import Finding, Severity
from ludvig.providers import FileSystemProvider
from ._common import BaseScanner


class FilesystemScanner(BaseScanner):
    def __init__(
        self,
        provider: FileSystemProvider,
        severity_level: Severity = Severity.MEDIUM,
        deobfuscated=False,
    ) -> None:
        super().__init__(deobfuscated)
        self.provider = provider
        self.severity_level = severity_level
        self.findings: List[Finding] = []

    def scan(self):
        for file_data, filename, extra in self.provider.get_files():
            findings = self.scan_file_data(file_data, filename, meta=extra)
            self.register_findings(findings)
