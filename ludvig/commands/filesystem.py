from ludvig.types import Severity
from ludvig.scanners import FilesystemScanner

def scan(
    path: str,
    custom_rules: str = None,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
    output_sarif = None
):
    """
    Scans a filesystem path
    :param path: Path to scan
    :param custom_rules: Path to any custom YARA rules (need to have .yar extension)
    :param severity_level: Set severity level for reporting
    :param deobfuscated: Returns any secrets found in plaintext. Defaults to False.
    :param output_sarif: Generates SARIF report if filename is specified.
    """
    if isinstance(severity_level, str):
        severity_level = Severity[severity_level]
    scanner = FilesystemScanner(path, severity_level, deobfuscated, custom_rules)
    scanner.scan()
    if output_sarif:
            from ludvig.outputs import SarifConverter
            report = SarifConverter.from_findings(scanner.findings)
            with open(output_sarif, "w") as r:
                r.write(report)
    return scanner.findings