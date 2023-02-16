import os
from unittest import TestCase
import mock
from ludvig.scanners import VulnerabilityScanner
from ludvig import Severity
from ludvig.config import Config
from ludvig.vulndb import Advisory, Package
import ludvig.vulndb


class TestVulnDb(ludvig.vulndb.VulnDb):
    def __init__(self) -> None:
        pass

    def query_advisory(
        self,
        package_name: str,
        ecosystem: str,
        version: str,
    ):
        if package_name == "Newtonsoft.Json":
            return [
                Advisory(
                    1,
                    "test",
                    None,
                    Package("Newtonsoft.Json"),
                    "nuget",
                    None,
                    "test advisory",
                    "0",
                )
            ]
        return []


class TestVulnDbDotNet(TestCase):
    def test_can_detect_vulnerable_package_in_project(self):
        deps_file = os.path.join(
            os.path.dirname(__file__), "fixtures/dotnet.deps-example.json"
        )
        config = Config("test", rule_sources=[], vulndb_sources=[])
        scanner = VulnerabilityScanner(TestVulnDb(), config)
        with open(deps_file, "r") as f:
            findings = scanner.scan_file_data(f, "deps.json", Severity.MEDIUM)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].filename, "Newtonsoft.Json")
