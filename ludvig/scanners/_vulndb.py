from typing import IO, List
from ludvig import Finding, Severity
from ludvig.config import Config
from ._common import BaseScanner
from ludvig.vulndb import VulnDb
from ludvig.parsers.dotnet_deps import parse_dotnet_deps, parse_dotnet_proj


class VulnerabilityScanner(BaseScanner):
    def __init__(self, vuln_db: VulnDb, config: Config) -> None:
        super().__init__(False, config)
        self.__db = vuln_db
        self.__parsers = [parse_dotnet_deps, parse_dotnet_proj]

    def scan_file_data(
        self, file_data: IO[bytes], file_name: str, severity_level: Severity, **kwargs
    ) -> List[Finding]:
        findings = []
        for parser in self.__parsers:
            packages = parser(file_data.read())
            for package in packages:
                results = self.__db.query_advisory(
                    package_name=package["name"],
                    ecosystem=package["ecosystem"],
                    version=package["version"],
                )
                for result in results:
                    findings.append(
                        Finding.from_vuln_advisory(
                            result, package["version"], file_name
                        )
                    )
        return findings

    def accepted_files(self) -> List[str]:
        return ["*.deps.json", "*.csproj"]
