from typing import IO, List
from ludvig.types import Finding, Severity
from ludvig.providers import BaseFileProvider
from knack.log import get_logger

logger = get_logger(__name__)


class BaseScanner:
    def __init__(self, deobfuscated=False) -> None:
        self.deobfuscated = deobfuscated

    def scan_file_data(
        self, file_data: IO[bytes], file_name: str, severity_level: Severity, **kwargs
    ) -> List[Finding]:
        pass


class ScanPipeline:
    def __init__(
        self,
        scanners: List[BaseScanner],
        provider: BaseFileProvider,
        severity_level: Severity = Severity.MEDIUM,
    ) -> None:
        self.__scanners = scanners
        self.__provider = provider
        self.__findings: List[Finding] = []
        self.__severity_level = severity_level

    def scan(self):
        for file_data, filename, properties in self.__provider.get_files():
            for scanner in self.__scanners:
                if not hasattr(scanner, "scan_file_data"):
                    logger.error(
                        "%s does not implement required method 'scan_file_data'",
                        scanner.__class__.__name__,
                    )
                logger.info("scanning using %s", scanner.__class__.__name__)
                findings = scanner.scan_file_data(
                    file_data, filename, self.__severity_level, **properties
                )
                self.register_findings(findings)

    def register_findings(self, findings: List[Finding]):
        unique_hashes = {f.hash for f in self.__findings}
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
