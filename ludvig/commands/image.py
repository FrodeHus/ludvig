from ludvig.scanners import ImageScanner
from ludvig.types import Severity
from ludvig.providers import ContainerProvider


def scan(
    repository: str,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
    output_sarif=None,
    include_first_layer=False,
    max_file_size=10000,
):
    """
    Scans a container image
    :param repository: Container image to scan (ex: myimage:1.1)
    :param severity_level: Set severity level for reporting
    :param deobfuscated: Returns any secrets found in plaintext. Default: False.
    :param output_sarif: Generates SARIF report if filename is specified.
    :param include_first_layer: Scan first layer (base image) as well - may affect speed. Default: False.
    :param max_file_size: Max file size for scanning (in bytes).
    """
    if isinstance(severity_level, str):
        severity_level = Severity[severity_level]
    provider = ContainerProvider(
        repository, include_first_layer, max_file_size=max_file_size
    )
    scanner = ImageScanner(provider, severity_level, deobfuscated)
    scanner.scan()
    if output_sarif:
        from ludvig.outputs import SarifConverter

        report = SarifConverter.from_findings(scanner.get_unique_findings())
        with open(output_sarif, "w") as r:
            r.write(report)
    return scanner.get_unique_findings()


def list_whiteouts(repository: str, include_first_layer=False):
    """
    Scans a container image for deleted files
    :param repository: Container image to scan
    :param include_first_layer: Scan first layer (base image) as well - may affect speed. Defaults to False.
    """
    provider = ContainerProvider(repository, include_first_layer)
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
