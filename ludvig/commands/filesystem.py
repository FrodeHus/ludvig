from ludvig import Severity
from ludvig.scanners import ScanPipeline, SecretScanner, VulnerabilityScanner
from ludvig.providers import FileSystemProvider
from ludvig.config import get_config
from ludvig.vulndb import get_vuln_db


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
    config = get_config()
    pipeline = ScanPipeline(
        [
            SecretScanner(config, deobfuscated),
            VulnerabilityScanner(get_vuln_db(config), config),
        ],
        provider,
        severity_level,
    )
    pipeline.scan()
    if output_sarif:
        from ludvig.outputs import SarifConverter

        report = SarifConverter.from_findings(pipeline.findings)
        with open(output_sarif, "w") as r:
            r.write(report)
    return pipeline.findings
