from types import MappingProxyType
from typing import List
from ludvig.types import Finding, FindingSample, RuleMatch, Severity, YaraRuleMatch
import sarif_om as sarif
from jschema_to_python.to_json import to_json

level_mapper = MappingProxyType(
    {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "warning",
        "UNKNOWN": "note",
    }
)

ludvig_tool = sarif.Tool(
    driver=sarif.ToolComponent(
        name="Ludvig by Reothor SARIF Report",
        full_name="Ludvig by Reothor SARIF Report",
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
                schema_uri="http://json.schemastore.org/sarif-2.1.0-rtm.4",
                runs=[run],
            )
        )

    @staticmethod
    def to_sarif_rule_id(rule_match: RuleMatch) -> str:
        return "_".join((rule_match.category.lower(), rule_match.rule_name.lower()))

    @staticmethod
    def to_sarif_level(finding: Finding) -> str:
        return level_mapper.get(finding.match.severity, "none")

    @staticmethod
    def findings_to_results(findings: List[Finding]) -> List[sarif.Result]:
        results = []
        for finding in findings:
            result = sarif.Result(
                rule_id=SarifConverter.to_sarif_rule_id(finding.match),
                level=SarifConverter.to_sarif_level(finding),
                locations=[SarifConverter.to_sarif_location(finding)],
                message=SarifConverter.to_message(finding.samples),
            )
            results.append(result)
        return results

    @staticmethod
    def to_region(finding: Finding) -> sarif.Region:
        return sarif.Region(
            start_line=1,
            start_column=finding.samples[0].offset,
            end_line=1,
            end_column=finding.samples[0].offset + len(finding.samples[0].content),
        )

    @staticmethod
    def to_sarif_location(finding: Finding) -> sarif.Location:
        return sarif.Location(
            physical_location=sarif.PhysicalLocation(
                artifact_location=sarif.ArtifactLocation(
                    uri=finding.filename, uri_base_id="EXECUTIONROOT"
                ),
                region=SarifConverter.to_region(finding),
            ),
        )

    @staticmethod
    def to_message(samples: List[FindingSample]) -> sarif.Message:
        return sarif.Message(text=",".join([s.content for s in samples]))

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
            )
            rules.append(rule)
        return rules
