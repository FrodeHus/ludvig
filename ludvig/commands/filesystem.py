from ludvig.types import Severity
from ludvig.scanners import FilesystemScanner
from ludvig.providers import FileSystemProvider


def scan(
    path: str,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
    output_sarif=None,
    max_file_size=10000,
):
    """
    Scans a filesystem path
    :param path: Path to scan
    :param severity_level: Set severity level for reporting
    :param deobfuscated: Returns any secrets found in plaintext. Default: False.
    :param output_sarif: Generates SARIF report if filename is specified.
    :param max_file_size: Max file size for scanning (in bytes).
    """
    if isinstance(severity_level, str):
        severity_level = Severity[severity_level]
    provider = FileSystemProvider(path, max_file_size=max_file_size)
    scanner = FilesystemScanner(provider, severity_level, deobfuscated)
    scanner.scan()
    if output_sarif:
        from ludvig.outputs import SarifConverter

        report = SarifConverter.from_findings(scanner.get_unique_findings())
        with open(output_sarif, "w") as r:
            r.write(report)
    return scanner.get_unique_findings()
