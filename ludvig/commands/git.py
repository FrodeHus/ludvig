from ludvig.types import Severity
from ludvig.providers import GitRepositoryProvider
from ludvig.scanners import FilesystemScanner


def scan(
    path: str,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
    output_sarif=None,
    max_file_size=10000,
):
    """
    Scans the history of a Git repository
    :param path: Path to Git repository
    :param severity_level: Set severity level for reporting
    :param deobfuscated: Returns any secrets found in plaintext. Default: False.
    :param output_sarif: Generates SARIF report if filename is specified.
    :param max_file_size: Max file size for scanning (in bytes).
    """
    if isinstance(severity_level, str):
        severity_level = Severity[severity_level]

    git_provider = GitRepositoryProvider(path)
    scanner = FilesystemScanner(git_provider, severity_level, deobfuscated)
    scanner.scan()
    if output_sarif:
        from ludvig.outputs import SarifConverter

        report = SarifConverter.from_findings(scanner.get_unique_findings())
        with open(output_sarif, "w") as r:
            r.write(report)
    return scanner.get_unique_findings()
