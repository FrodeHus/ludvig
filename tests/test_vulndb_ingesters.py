import os
from unittest import TestCase
from ludvig.vulndb.ingesters import github_read_advisory, github_read_repository
from ludvig.vulndb import OSVPackage, OSVRange, OSVEvent, OSVulnerability


class TestParseGitHubAdvisory(TestCase):
    def test_parse_advisory(self):
        ghsa_file = os.path.join(
            os.path.dirname(__file__), "fixtures/ghsa/GHSA-abcde-001.json"
        )
        advisory = github_read_advisory(ghsa_file)
        self.assertIsNotNone(advisory)
        self.assertEqual(len(advisory.affected), 1)
        self.assertEqual(len(advisory.affected[0].ranges), 1)
        self.assertEqual(len(advisory.affected[0].ranges[0].events), 2)
        self.assertEqual(advisory.database_specific["github_reviewed"], True)

    def test_read_repository(self):
        repo = os.path.join(os.path.dirname(__file__), "fixtures/ghsa")
        advisories = list(github_read_repository(repo))
        self.assertEqual(len(advisories), 2)


class TestOpenSourceVulnerabilityValidations(TestCase):
    def test_id_prefix_validation(self):
        expected_prefixes = [
            "A",
            "GO",
            "OSV",
            "PYSEC",
            "RUSTSEC",
            "GSD",
            "GHSA",
            "LBSEC",
            "DSA",
            "DLA",
            "DTSA",
            "CVE",
        ]
        for prefix in expected_prefixes:
            id = "%s-test-advisory" % prefix
            with self.subTest(prefix=prefix):
                OSVulnerability(
                    id,
                    "2023-01-01T15:21:32.59+02:00",
                    None,
                    None,
                    None,
                    None,
                    [],
                    [],
                    [],
                )

    def test_ecosystem_validation(self):
        expected_ecosystems = [
            "go",
            "npm",
            "oss-fuzz",
            "pypi",
            "rubygems",
            "crates.io",
            "packagist",
            "maven",
            "nuget",
            "linux",
            "debian",
            "alpine",
            "hex",
            "android",
            "github actions",
            "pub",
        ]
        for ecosystem in expected_ecosystems:
            with self.subTest(ecosystem=ecosystem):
                OSVPackage(ecosystem, "test")

    def test_range_validation(self):
        test_cases = [
            {
                "type": "git",
                "repo": "test/repo",
                "events": [OSVEvent(introduced="2023-01-01T15:21:32.59+02:00")],
            },
            {
                "type": "semver",
                "repo": None,
                "events": [OSVEvent(introduced="2023-01-01T15:21:32.59+02:00")],
            },
            {
                "type": "ecosystem",
                "repo": None,
                "events": [OSVEvent(introduced="2023-01-01T15:21:32.59+02:00")],
            },
        ]
        for case in test_cases:
            with self.subTest(type=case["type"], repo=case["repo"]):
                OSVRange(case["type"], case["events"], repo=case["repo"])
