from typing import IO, List

from ludvig.types import Finding, Severity
from ._common import BaseScanner


class VulnerabilityScanner(BaseScanner):
    def __init__(self, deobfuscated=False) -> None:
        super().__init__(deobfuscated)

    def scan_file_data(
        self, file_data: IO[bytes], file_name: str, severity_level: Severity, **kwargs
    ) -> List[Finding]:
        return []
