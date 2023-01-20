from unittest import TestCase
from ludvig.types import Finding, RuleMatch
from ludvig.outputs.sarif import Result

class TestSarifLogGenerator(TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        
    def test_result_from_finding(self) -> None:
        finding = Finding("secret", RuleMatch())
        result = Result()
        