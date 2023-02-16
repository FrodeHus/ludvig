from typing import IO, List
from ludvig.sbom.dotnet.dependencies import DotnetDependenciesParser
from cyclonedx.model.bom import Bom
from ludvig import Finding, Severity
from ludvig.config import Config
from ._common import BaseScanner
from ludvig.vulndb import VulnDb


class VulnerabilityScanner(BaseScanner):
    def __init__(self, vuln_db: VulnDb, config: Config) -> None:
        super().__init__(False, config)
        self.__db = vuln_db

    def scan_file_data(
        self, file_data: IO[bytes], file_name: str, severity_level: Severity, **kwargs
    ) -> List[Finding]:
        parser = DotnetDependenciesParser(dependency_content=file_data.read())
        bom = Bom.from_parser(parser)
        findings = []
        for component in bom.components:
            results = self.__db.query_advisory(
                package_name=component.name,
                ecosystem=component.purl.type,
                version=component.version,
            )
            for result in results:
                findings.append(
                    Finding.from_vuln_advisory(result, component.version, file_name)
                )
        return findings

    def accepted_files(self) -> List[str]:
        return ["*.deps.json"]
