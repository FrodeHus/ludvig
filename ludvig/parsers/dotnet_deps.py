from defusedxml.ElementTree import fromstring
import json


def parse_dotnet_proj(project_file: str):
    tree = fromstring(project_file)
    refs = tree.findall("*/PackageReference")
    return [
        {
            "name": r.attrib["Include"],
            "version": r.attrib["Version"] if "Version" in r.attrib else "0",
        }
        for r in refs
    ]


def parse_dotnet_deps(deps_file: str):
    deps_data = json.loads(deps_file)
    libs = deps_data["libraries"]
    return [
        {"name": lib[: lib.find("/")], "version": lib[lib.find("/") + 1 :]}
        for lib in libs
        if libs[lib]["type"] == "package"
    ]
