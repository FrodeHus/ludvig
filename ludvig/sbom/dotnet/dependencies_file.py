import json

class DependenciesFile:
    def __init__(self) -> None:
        pass
    
    @classmethod
    def from_string(cls, content : str) -> "DependenciesFile":
        deps = json.loads(content)
        libs = []
        for _, item in enumerate(deps["libraries"]):
            if item["type"] != "package":
                continue
            libs.append(item)