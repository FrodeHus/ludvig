from typing import List
from ludvig.types import Finding, Severity, YaraRuleMatch
import yara

class Driver:
    def __init__(self, name : str, information_url : str) -> None:
        self.name = name
        self.full_name = name
        self.information_url = information_url
        self.rules : List[Rule] = []
        
class Tool:
    def __init__(self, driver : Driver) -> None:
        self.driver = driver

class Artifact:
    def __init__(self, location : str) -> None:
        self.location = location
        
class Rule:
    def __init__(self, id : str, description: str, help_uri : str = None, category = None) -> None:
        self.id = id
        self.short_description = {
            "text": description
        }
        self.help_uri = help_uri,
        self.properties = {
            "category": category
        }
        
    @staticmethod
    def from_findings(findings : List[Finding]) -> List["Rule"]:
        rules = []
        for finding in findings:
            rule_id = finding.match.rule_name
            description = finding.match.description
            category = finding.match.category
            rule = Rule(rule_id, description, help_uri=None, category=category)
            rules.append(rule)
        return list({r.id: r for r in rules}.values())
        
class Result:
    def __init__(self, rule_id : str, level : str, locations : List[str]) -> None:
        self.rule_id = rule_id
        self.level = level
        self.locations = locations

class Run:
    def __init__(self, tool : Tool = None, artifacts : List[Artifact] = None, results : List[Result] = None) -> None:
        self.tool = tool or Tool(Driver("Ludvig", "https://github.com/frodehus/ludvig"))
        self.artifacts = artifacts or []
        self.results = results or []

class SarifLog:
    def __init__(self, runs : List[Run]) -> None:
        self.version = "2.1.0"
        self.schema = "http://json.schemastore.org/sarif-2.1.0-rtm.4"
        self.runs = runs
        
    @classmethod   
    def from_findings(cls, findings : List[Finding]) -> "SarifLog":
        run = Run()
        run.tool.driver.rules = Rule.from_findings(findings)
        for finding in findings:                      
            result = Result(finding.match.rule_name, finding.match.severity, [finding.filename])
            run.results.append(result)
            
        log = SarifLog([run])
        return log