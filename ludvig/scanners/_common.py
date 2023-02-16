import abc
import fnmatch
from typing import IO, Dict, List
from ludvig._types import Finding, Severity
from ludvig.providers import BaseFileProvider
from ludvig.config import Config
from knack.log import get_logger

logger = get_logger(__name__)


class BaseScanner(abc.ABC):
    def __init__(self, config: Config, deobfuscated=False) -> None:
        self.config = config
        self.deobfuscated = deobfuscated

    @abc.abstractmethod
    def scan_file_data(
        self, file_data: IO[bytes], file_name: str, severity_level: Severity, **kwargs
    ) -> List[Finding]:
        """Scans the provided file and reports any findings that matches the given severity level.

        Args:
            file_data (IO[bytes]): The actual file content
            file_name (str): Name of the file
            severity_level (Severity): Severity level to report on

        Keyword Arguments:
            Any additional keyword arguments are added as properties to the finding (metadata)

        Returns:
            List[Finding]: Security issues detected
        """
        pass

    @abc.abstractmethod
    def accepted_files(self) -> List[str]:
        pass

    def accepts_file(self, filename: str):
        for accepted in self.accepted_files():
            if fnmatch.fnmatch(filename, accepted):
                return True
        return False


class ScanPipeline:
    def __init__(
        self,
        scanners: List[BaseScanner],
        provider: BaseFileProvider,
        severity_level: Severity = Severity.MEDIUM,
    ) -> None:
        self.__scanners = scanners
        self.__provider = provider
        self.findings: Dict[str, List[Finding]] = {}
        self.__severity_level = severity_level

    def scan(self):
        """Scans every file returned by the given provider using the provided list of scanners."""
        for file_data, filename, properties in self.__provider.get_files():
            for scanner in self.__scanners:
                if not hasattr(scanner, "scan_file_data"):
                    logger.error(
                        "%s does not implement required method 'scan_file_data'",
                        scanner.__class__.__name__,
                    )
                logger.info("scanning using %s", scanner.__class__.__name__)
                if not scanner.accepts_file(filename):
                    continue
                findings = scanner.scan_file_data(
                    file_data, filename, self.__severity_level, **properties
                )
                if hasattr(file_data, "seek") and callable(getattr(file_data, "seek")):
                    file_data.seek(0)
                self.register_findings(findings)
        self.close_scanners()

    def close_scanners(self):
        for scanner in self.__scanners:
            if hasattr(scanner, "close") and callable(getattr(scanner, "close")):
                scanner.close()

    def register_findings(self, findings: List[Finding]):
        unique_hashes = []
        for category in self.findings:
            unique_hashes.extend([f._hash for f in self.findings[category]])

        for finding in findings:
            if finding._hash in unique_hashes:
                continue

            category = finding.properties["category"]
            if category not in self.findings:
                self.findings[category] = []
            self.findings[category].append(finding)
