from unittest import TestCase
from ludvig.types import Finding, RuleMatch, Severity
from ludvig.outputs import SarifConverter


class TestSarifLogGenerator(TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)

    def test_result_from_finding(self) -> None:
        finding = Finding(
            "secret",
            RuleMatch("GitHub Token", Severity.CRITICAL, "secrets", "Test rule"),
            None,
            "testfile.json",
        )
        report = SarifConverter.from_findings([finding])
        self.assertEqual(len(report.runs[0].results), 1)
