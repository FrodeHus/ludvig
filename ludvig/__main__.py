import json
import sys
import tarfile
import argparse
from typing import List
from ludvig.client import DockerClient
from ludvig.rules.loader import load_yara_rules
from ludvig.types import Finding, Image, Layer, Severity
from ludvig.scanners import FilesystemScanner, Finding, Image, ImageScanner
from ludvig.outputs import PrettyConsole, JsonOutput
from rich.progress import Progress
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
        "--output", help="Output format", choices=["pretty", "json"], default="pretty"
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
            findings = scan_image(
                args.name, yara_rules, severity_level, args.deobfuscated
            )
        elif args.scan_type == "fs":
            findings = scan_filesystem(
                args.path, yara_rules, severity_level, args.deobfuscated
            )
        progress.remove_task(scan_task)

    if len(findings) > 0:
        output_provider = get_output_provider(args.output, findings)
        output_provider.output()
        sys.exit(2)


def get_output_provider(provider: str, findings: List[Finding]):
    if provider == "pretty":
        return PrettyConsole(findings)
    elif provider == "json":
        return JsonOutput(findings)


def scan_image(
    image: str,
    rules: yara.Rules,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
) -> List[Finding]:
    with read_image(image) as image:
        scanner = ImageScanner(image, rules, severity_level, deobfuscated)
        scanner.scan()
        return scanner.findings


def scan_filesystem(
    path: str,
    rules: yara.Rules,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
) -> List[Finding]:
    scanner = FilesystemScanner(path, rules, severity_level, deobfuscated)
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
