from cyclonedx.model.component import Component
from cyclonedx.parser import BaseParser
from packageurl import PackageURL

from ludvig.sbom.dotnet.dependencies_file import DependenciesFile


class DotnetDependenciesParser(BaseParser):
    def __init__(self, dependency_content: str) -> None:
        super().__init__()

        deps = DependenciesFile.from_string(dependency_content)
        for lib in deps.libraries:
            # hashes = map(HashType.from_composite_str(lib.sha512))
            self._components.append(
                Component(
                    name=lib.name,
                    version=lib.version,
                    purl=PackageURL(type="nuget", name=lib.name, version=lib.version),
                )
            )
