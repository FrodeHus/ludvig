import os
from unittest import TestCase
from ludvig.vulndb.ingesters import github_read_advisory


class TestParseGitHubAdvisory(TestCase):
    def test_parse_advisory(self):
        ghsa_file = os.path.join(os.path.dirname(__file__), "fixtures/ghsa_001.json")
        advisory = github_read_advisory(ghsa_file)
        self.assertIsNotNone(advisory)
        self.assertEqual(len(advisory.affected), 1)
        self.assertEqual(len(advisory.affected[0].ranges), 1)
        self.assertEqual(len(advisory.affected[0].ranges[0].events), 2)
