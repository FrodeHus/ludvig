import json
import sys
import tarfile
import argparse
from typing import List
from ludvig.client import DockerClient
from ludvig.rules.loader import load_yara_rules
from ludvig.types import Finding, Image, Layer
from ludvig.scanners.filesystem import FilesystemScanner
from ludvig.scanners.container import ImageScanner
from rich.table import Table
from rich.console import Console, OverflowMethod
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
    sub_parsers = parser.add_subparsers(dest="scan_type")
    image_parser = sub_parsers.add_parser("image", help="scan container")
    image_parser.add_argument("name", help="Container image to scan (ex: myimage:1.1)")
    fs_parser = sub_parsers.add_parser("fs", help="scan filesystem")
    fs_parser.add_argument("path", help="Path to scan")
    args = parser.parse_args()

    yara_rules = load_yara_rules(custom=args.custom_rules)
    if args.scan_type == "image":
        findings = scan_image(args.name, yara_rules)
    elif args.scan_type == "fs":
        findings = scan_filesystem(args.path, yara_rules)

    output(findings, args.deobfuscated)
    if len(findings) > 0:
        sys.exit(2)


def output(findings: List[Finding], obfuscate: bool = True):
    table = Table(title="Findings")
    table.add_column("Rule", style="cyan")
    table.add_column("Filename", style="cyan", overflow="fold")
    table.add_column("Content", style="red")
    for finding in findings:
        table.add_row(
            "{}\r\n[green]{}[/]".format(finding.match.rule_name, finding.category),
            "{} {}".format(
                finding.filename, (":cross_mark:" if finding.whiteout else "")
            ),
            finding.obfuscated_content if not obfuscate else finding.content,
        )

    console = Console()
    console.print(table)


def scan_image(image: str, rules: yara.Rules) -> List[Finding]:
    with read_image(image) as image:
        scanner = ImageScanner(image, rules)
        scanner.scan()
        return scanner.findings


def scan_filesystem(path: str, rules: yara.Rules) -> List[Finding]:
    scanner = FilesystemScanner(path, rules)
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

    layers = []
    for idx, layer in enumerate(manifest[0]["Layers"]):
        layer_id = layer[: layer.index("/")]
        layer_history = get_layer_history(config, idx + 1)
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
    return Image(manifest[0]["RepoTags"], layers, img)


def get_layer_history(config: dict, layer_index: int):
    return config["history"][layer_index]


if __name__ == "__main__":
    main()
