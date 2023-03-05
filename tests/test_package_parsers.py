from unittest import TestCase
from ludvig.parsers.dotnet_deps import parse_dotnet_deps, parse_dotnet_proj
from ludvig.parsers.npm import parse_package_lock
import os


class TestPackageParsers(TestCase):
    def test_parse_dotnet_csproj(self) -> None:
        proj_file = os.path.join(os.path.dirname(__file__), "fixtures/dotnet.csproj")
        with open(proj_file) as f:
            packages = parse_dotnet_proj(f.read())
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["name"], "Newtonsoft.Json")
        self.assertEqual(packages[0]["version"], "13.0.2")

    def test_parse_dotnet_deps(self) -> None:
        deps_file = os.path.join(
            os.path.dirname(__file__), "fixtures/dotnet.deps-example.json"
        )
        with open(deps_file) as f:
            packages = parse_dotnet_deps(f.read())
            self.assertEqual(len(packages), 2)
            self.assertEqual(packages[0]["name"], "IdentityModel")
            self.assertEqual(packages[0]["version"], "6.0.0")

    def test_parse_npm_packages(self) -> None:
        package_file = os.path.join(
            os.path.dirname(__file__), "fixtures/package-lock.json"
        )
        with open(package_file) as f:
            packages = parse_package_lock(f.read())

        self.assertEqual(len(packages), 282)
        self.assertEquals(packages[0], {"name": "@babel/runtime", "version": "7.21.0"})
