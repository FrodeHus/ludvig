from unittest import TestCase
import os
from ludvig.sbom.dotnet.dependencies import DotnetDependenciesParser

class TestDotnetDependenciesParser(TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        
    def test_simple(self) -> None:
        with open(os.path.join(os.path.dirname(__file__),
                               'fixtures/dotnet.deps-example.json')) as r:
            parser = DotnetDependenciesParser(dependency_content=r.read())