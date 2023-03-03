from defusedxml.ElementTree import parse


def parse_dotnet_proj(project_file: str):
    tree = parse(project_file)
    refs = tree.findall("*/PackageReference")
    return [
        {
            "name": r.attrib["Include"],
            "version": r.attrib["Version"] if "Version" in r.attrib else "0",
        }
        for r in refs
    ]
