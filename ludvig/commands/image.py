from ludvig.scanners import ImageScanner
from ludvig.types import Severity
from ludvig.providers import ContainerProvider


def scan(
    repository: str,
    custom_rules: str = None,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
    output_sarif=None,
):
    """
    Scans a container image
    :param repository: Container image to scan (ex: myimage:1.1)
    :param custom_rules: Path to any custom YARA rules (need to have .yar extension)
    :param severity_level: Set severity level for reporting
    :param deobfuscated: Returns any secrets found in plaintext. Defaults to False.
    :param output_sarif: Generates SARIF report if filename is specified.
    """
    if isinstance(severity_level, str):
        severity_level = Severity[severity_level]
    provider = ContainerProvider(repository)
    scanner = ImageScanner(provider, severity_level, deobfuscated, custom_rules)
    scanner.scan()
    if output_sarif:
        from ludvig.outputs import SarifConverter

        report = SarifConverter.from_findings(scanner.findings)
        with open(output_sarif, "w") as r:
            r.write(report)
    return scanner.findings


def list_whiteouts(repository: str):
    """
    Scans a container image for deleted files
    :param repository: Container image to scan
    """
    provider = ContainerProvider(repository)
    scanner = ImageScanner(provider)
    return scanner.list_whiteout()


def extract_file(repository: str, filename: str, output_file: str):
    """
    Extracts a file from the specified container image (even if marked as deleted) - first occurence only
    :param repository: Container image to read from
    :param filename: File to extract (full path)
    :param output_file: Output file
    """
    provider = ContainerProvider(repository)
    scanner = ImageScanner(provider)
    scanner.extract_file(filename, output_file)
