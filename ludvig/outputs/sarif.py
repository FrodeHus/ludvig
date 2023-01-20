from typing import List
from ludvig.types import Finding, Severity
class Driver:
    def __init__(self, name : str, information_url : str) -> None:
        self.name = name
        self.information_url = information_url
        
class Tool:
    def __init__(self, driver : Driver) -> None:
        self.driver = driver

class Artifact:
    def __init__(self, location : str) -> None:
        self.location = location
        
class Rule:
    def __init__(self, rule_id : str, level : Severity) -> None:
        self.rule_id = rule_id
        self.level = level
        
class Result:
    def __init__(self) -> None:
        pass

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
        for finding in findings: 
            result = Result()
            run.results.append(result)
            
        log = SarifLog([run])
        return log