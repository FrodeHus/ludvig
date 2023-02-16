from ludvig.scanners import SecretScanner, VulnerabilityScanner, ScanPipeline
from ludvig import Severity
from ludvig.providers import ContainerProvider
from ludvig.config import get_config
from ludvig.vulndb import get_vuln_db


def scan(
    repository: str,
    severity_level: Severity = Severity.MEDIUM,
    enabled=["secret", "vuln"],
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
    config = get_config()
    scanners = []
    if "secret" in enabled:
        scanners.append(SecretScanner(config, deobfuscated))
    if "vuln" in enabled:
        scanners.append(VulnerabilityScanner(get_vuln_db(config), config))

    pipeline = ScanPipeline(scanners, provider, severity_level)
    pipeline.scan()
    if output_sarif:
        from ludvig.outputs import SarifConverter

        report = SarifConverter.from_findings(pipeline.findings)
        with open(output_sarif, "w") as r:
            r.write(report)
    return pipeline.findings


# def list_whiteouts(repository: str, include_first_layer=False):
#     """
#     Scans a container image for deleted files
#     :param repository: Container image to scan
#     :param include_first_layer: Scan first layer (base image) as well - may affect speed. Defaults to False.
#     """
#     provider = ContainerProvider(repository, include_first_layer)
#     scanner = ImageScanner(provider)
#     return scanner.list_whiteout()
