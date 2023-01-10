import json
from typing import IO
from cyclonedx.model.component import Component
from cyclonedx.parser import BaseParser, ParserWarning
from packageurl import PackageURL

from ludvig.sbom.dotnet.dependencies_file import DependenciesFile


class DotnetDependenciesParser(BaseParser):
    def __init__(self, dependency_content : str) -> None:
        super().__init__()
        
        deps = DependenciesFile.from_string(dependency_content)
