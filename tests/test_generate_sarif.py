import json
from unittest import TestCase
from ludvig import Finding, FindingSample, RuleMatch, Severity
from ludvig.outputs import SarifConverter


class TestSarifLogGenerator(TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)

    def test_result_from_finding(self) -> None:
        sample = FindingSample("test", 0)
        finding = Finding(
            1,
            "secret",
            RuleMatch(
                "test", "GitHub Token", Severity.CRITICAL, "secrets", "Test rule"
            ),
            "testfile.json",
            [sample],
        )
        report = SarifConverter.from_findings([finding])
        report = json.loads(report)
        self.assertEqual(len(report["runs"][0]["results"]), 1)
