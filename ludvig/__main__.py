import json
import pprint
import sys
import tarfile
import argparse
from typing import List
from ludvig.client import DockerClient
from ludvig.rules.loader import load_yara_rules
from ludvig.types import Finding, Image, Layer, Severity
from ludvig.scanners.filesystem import FilesystemScanner
from ludvig.scanners.container import ImageScanner
from rich.table import Table
from rich.progress import Progress
from rich.console import Console
import yara


def main():
    parser = argparse.ArgumentParser(prog="ludvig")
    parser.add_argument(
        "--deobfuscated",
        help="Shows any detected secrets without obfuscation",
        action="store_true",
    )
    parser.add_argument(
        "--custom-rules", help="Path to custom YARA rules (need to have .yar extension)"
    )
    parser.add_argument(
        "--level",
        help="Only report findings above the given level",
        choices=[e.name for e in Severity],
        default="MEDIUM",
    )
    sub_parsers = parser.add_subparsers(dest="scan_type")
    image_parser = sub_parsers.add_parser("image", help="scan container")
    image_parser.add_argument("name", help="Container image to scan (ex: myimage:1.1)")
    fs_parser = sub_parsers.add_parser("fs", help="scan filesystem")
    fs_parser.add_argument("path", help="Path to scan")
    args = parser.parse_args()
    severity_level = Severity[args.level]
    yara_rules = load_yara_rules(custom=args.custom_rules)
    with Progress() as progress:
        scan_task = progress.add_task("[green]Scanning...", total=None)
        if args.scan_type == "image":
            findings = scan_image(args.name, yara_rules, severity_level)
        elif args.scan_type == "fs":
            findings = scan_filesystem(args.path, yara_rules, severity_level)
        progress.remove_task(scan_task)

    if len(findings) > 0:
        output(findings, args.deobfuscated)
        sys.exit(2)


def output(findings: List[Finding], deobfuscated: bool = False):
    table = Table(title="Findings", show_lines=True)
    table.add_column("Rule", style="white")
    table.add_column("Filename", style="white", overflow="fold")
    table.add_column("Content", style="red")
    for finding in findings:
        table.add_row(
            "{}: {}\r\n[gray50]{}[/]".format(
                color_coded_severity(finding.match.severity),
                finding.match.rule_name,
                ", ".join(finding.match.tags),
            ),
            "{} {}\r\n[gray50]{}{}[/]".format(
                finding.filename,
                (":cross_mark:" if finding.whiteout else ""),
                "Created by: [yellow]{}[/]".format(prettify(finding.comment)),
                "\r\nRemoved by: [yellow]{}[/]".format(prettify(finding.removed_by))
                if finding.removed_by
                else "",
            ),
            format_samples(finding, deobfuscated),
        )

    console = Console()
    console.print(table)


def format_samples(finding: Finding, deobfuscated=False):
    output = ""
    for sample in finding.samples:
        output += "[yellow]{0:<5d}[/]: {1}\r\n".format(
            sample.offset, sample.content if deobfuscated else sample.obfuscated_content
        )
    return output


def prettify(s: str) -> str:
    if s is None:
        return s
    s = s[: s.index("#") if "#" in s else len(s)]
    return s.replace("/bin/sh -c", "")


def color_coded_severity(severity: Severity):
    match severity:
        case "MEDIUM":
            return "[yellow]{0:<10s}[/]".format(severity)
        case "HIGH":
            return "[magenta]{0:<10s}[/]".format(severity)
        case "CRITICAL":
            return "[red]{0:<10s}[/]".format(severity)
        case _:
            return "[bright_black]{0:<10s}[/]".format(severity)


def scan_image(
    image: str, rules: yara.Rules, severity_level: Severity = Severity.MEDIUM
) -> List[Finding]:
    with read_image(image) as image:
        scanner = ImageScanner(image, rules, severity_level)
        scanner.scan()
        return scanner.findings


def scan_filesystem(
    path: str, rules: yara.Rules, severity_level: Severity = Severity.MEDIUM
) -> List[Finding]:
    scanner = FilesystemScanner(path, rules, severity_level)
    scanner.scan()
    return scanner.findings


def read_image(name: str) -> Image:
    client = DockerClient()
    file = client.export_image(name)
    if not tarfile.is_tarfile(file):
        raise Exception("Not an image")
    file.seek(0)
    img = tarfile.open(fileobj=file)
    with img.extractfile("manifest.json") as mf:
        manifest = json.load(mf)
    with img.extractfile(manifest[0]["Config"]) as cf:
        config = json.load(cf)

    file_layers = [layer for layer in config["history"] if not "empty_layer" in layer]
    layers = []
    for idx, layer in enumerate(manifest[0]["Layers"]):
        layer_id = layer[: layer.index("/")]
        layer_history = get_layer_history(file_layers, idx + 1)
        layers.append(
            Layer(
                layer_id,
                layer_history["created_by"],
                (
                    layer_history["empty_layer"]
                    if "empty_layer" in layer_history
                    else False
                ),
            )
        )
    return Image(manifest[0]["RepoTags"], layers, config["config"]["Env"], img)


def get_layer_history(config: dict, layer_index: int):
    return config[layer_index - 1]


if __name__ == "__main__":
    main()
