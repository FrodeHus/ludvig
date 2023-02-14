import os
from unittest import TestCase
from ludvig.scanners import VulnerabilityScanner
from ludvig.types import Severity


class TestVulnDbDotNet(TestCase):
    def test_can_detect_vulnerable_package_in_project(self):
        deps_file = os.path.join(
            os.path.dirname(__file__), "fixtures/dotnet.deps-example.json"
        )

        scanner = VulnerabilityScanner()
        with open(deps_file, "r") as f:
            findings = scanner.scan_file_data(f, "deps.json", Severity.MEDIUM)
        self.assertEqual(len(findings), 1)
        self.assertEquel(findings[0].match.rule_name, "Newtonsoft.Json")
