import os
from unittest import TestCase
import mock
from ludvig.scanners import VulnerabilityScanner
from ludvig import Severity
from ludvig.vulndb import Advisory, Package
import ludvig.vulndb


class TestVulnDbDotNet(TestCase):
    @mock.patch.object(ludvig.vulndb.VulnDb, "query_advisory", autospec=True)
    def test_can_detect_vulnerable_package_in_project(self, queryMock: mock.Mock):
        deps_file = os.path.join(
            os.path.dirname(__file__), "fixtures/dotnet.deps-example.json"
        )
        return_value = Advisory(
            1,
            "test",
            None,
            Package("Newtonsoft.Json"),
            "nuget",
            None,
            "test advisory",
            "0",
        )

        def side_effect(*args, **kwargs):
            if kwargs["package_name"] == "Newtonsoft.Json":
                return [return_value]
            return []

        queryMock.side_effect = side_effect
        scanner = VulnerabilityScanner()
        with open(deps_file, "r") as f:
            findings = scanner.scan_file_data(f, "deps.json", Severity.MEDIUM)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].filename, "Newtonsoft.Json")
        queryMock.assert_called_with(
            mock.ANY,
            package_name="Newtonsoft.Json",
            ecosystem="nuget",
            version="13.0.0",
        )
