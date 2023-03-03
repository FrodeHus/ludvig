from unittest import TestCase
import os
from ludvig.sbom.dotnet.dependencies import DotnetDependenciesParser
from cyclonedx.model.bom import Bom
from cyclonedx.output import OutputFormat, get_instance as get_output
from ludvig.parsers.dotnet_deps import parse_dotnet_proj


class TestDotnetDependenciesParser(TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)

    def test_simple(self) -> None:
        with open(
            os.path.join(os.path.dirname(__file__), "fixtures/dotnet.deps-example.json")
        ) as r:
            parser = DotnetDependenciesParser(dependency_content=r.read())
            bom = Bom.from_parser(parser)
            v = get_output(bom=bom, output_format=OutputFormat.JSON)

    def test_parse_dotnet_csproj(self) -> None:
        proj_file = os.path.join(os.path.dirname(__file__), "fixtures/dotnet.csproj")
        packages = parse_dotnet_proj(proj_file)
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["name"], "Newtonsoft.Json")
        self.assertEqual(packages[0]["version"], "13.0.2")
