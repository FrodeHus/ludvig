from types import MappingProxyType
from typing import List
from ludvig.types import Finding, FindingSample, RuleMatch, Severity, YaraRuleMatch
import sarif_om as sarif
from jschema_to_python.to_json import to_json

level_mapper = MappingProxyType(
    {
        "CRITICAL": "10",
        "HIGH": "8",
        "MEDIUM": "5",
        "LOW": "3",
        "UNKNOWN": "0",
    }
)

ludvig_tool = sarif.Tool(
    driver=sarif.ToolComponent(
        name="Ludvig SARIF Report",
        full_name="Ludvig by Reothor SARIF Report",
        semantic_version="0.2",
        information_uri="https://github.com/frodehus/ludvig",
    )
)


class SarifConverter:
    def from_findings(findings: List[Finding]) -> str:
        results = SarifConverter.findings_to_results(findings)
        ludvig_tool.driver.rules = SarifConverter.rules_from_findings(findings)
        run = sarif.Run(tool=ludvig_tool, results=results)
        return to_json(
            sarif.SarifLog(
                version="2.1.0",
                schema_uri="http://json.schemastore.org/sarif-2.1.0",
                runs=[run],
            )
        )

    @staticmethod
    def to_sarif_rule_id(rule_match: RuleMatch) -> str:
        return rule_match.id

    @staticmethod
    def to_sarif_level(finding: Finding) -> str:
        return level_mapper.get(finding.match.severity, "0")

    @staticmethod
    def findings_to_results(findings: List[Finding]) -> List[sarif.Result]:
        results = []
        for finding in findings:
            result = sarif.Result(
                rule_id=SarifConverter.to_sarif_rule_id(finding.match),
                locations=[SarifConverter.to_sarif_location(finding)],
                message=SarifConverter.to_message(finding.match),
            )
            results.append(result)
        return results

    @staticmethod
    def to_region(finding: Finding) -> sarif.Region:
        return sarif.Region(
            start_line=finding.samples[0].line_number,
        )

    @staticmethod
    def to_sarif_location(finding: Finding) -> sarif.Location:
        return sarif.Location(
            physical_location=sarif.PhysicalLocation(
                artifact_location=sarif.ArtifactLocation(
                    uri=finding.filename, uri_base_id="%SRCROOT%"
                ),
                region=SarifConverter.to_region(finding),
            ),
        )

    @staticmethod
    def to_message(rule_match: RuleMatch) -> sarif.Message:
        if rule_match.id.startswith("LS"):
            return sarif.Message(text="Secret or other sensitive information found")
        elif rule_match.id.startswith("LM"):
            return sarif.Message(text="Potentially malicious code")
        return sarif.Message(text="Unknown finding")

    @staticmethod
    def rules_from_findings(findings: List[Finding]) -> List[sarif.ReportingDescriptor]:
        rules = []
        for finding in findings:
            rule_id = finding.match.rule_name
            description = finding.match.description
            rule = sarif.ReportingDescriptor(
                id=SarifConverter.to_sarif_rule_id(finding.match),
                name=rule_id,
                short_description=sarif.MultiformatMessageString(
                    text=description, markdown=description
                ),
                properties=sarif.PropertyBag(),
            )
            setattr(
                rule.properties,
                "security-severity",
                SarifConverter.to_sarif_level(finding),
            )

            rules.append(rule)
        return rules
