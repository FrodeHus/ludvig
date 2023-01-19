import json
from typing import List


class DotnetLibrary:
    def __init__(
        self, name: str, version: str, path: str, sha512: str, hash_path: str
    ) -> None:
        self.name = name
        self.version = version
        self.path = path
        self.sha512 = sha512
        self.hash_path = hash_path


class DependenciesFile:
    def __init__(self, libraries: List[DotnetLibrary]) -> None:
        self.libraries = libraries

    @classmethod
    def from_string(cls, content: str) -> "DependenciesFile":
        deps = json.loads(content)
        libs = []
        for _, item in enumerate(deps["libraries"]):
            lib_data = deps["libraries"][item]
            if lib_data["type"] != "package":
                continue
            name_version = item.split("/")
            library = DotnetLibrary(
                name_version[0],
                name_version[1],
                lib_data["path"],
                lib_data["sha512"],
                lib_data["hashPath"],
            )
            libs.append(library)

        return DependenciesFile(libs)
