from defusedxml.ElementTree import fromstring
import json


def parse_dotnet_proj(project_file: str):
    import xml

    try:
        tree = fromstring(project_file)
    except xml.etree.ElementTree.ParseError:
        return []
    refs = tree.findall("*/PackageReference")
    return [
        {
            "ecosystem": "nuget",
            "name": r.attrib["Include"],
            "version": r.attrib["Version"] if "Version" in r.attrib else "0",
        }
        for r in refs
    ]


def parse_dotnet_deps(deps_file: str):
    try:
        deps_data = json.loads(deps_file)
    except json.JSONDecodeError:
        return []
    libs = deps_data["libraries"]
    return [
        {
            "ecosystem": "nuget",
            "name": lib[: lib.find("/")],
            "version": lib[lib.find("/") + 1 :],
        }
        for lib in libs
        if libs[lib]["type"] == "package"
    ]
