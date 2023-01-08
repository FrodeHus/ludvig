import json
import sys
import tarfile
import argparse
from ludvig.client import DockerClient
from ludvig.image_scanner import SecretsScanner
from ludvig.rules.loader import load_yara_rules
from ludvig.types import Image, Layer
from rich.table import Table
from rich.console import Console


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image", help="Container image to scan (ex: myimage:1.1)")
    parser.add_argument(
        "--deobfuscated",
        help="Shows any detected secrets without obfuscation",
        action="store_true",
    )
    args = parser.parse_args()

    yara_rules = load_yara_rules()
    with read_image(args.image) as image:
        scanner = SecretsScanner(image, yara_rules)
        scanner.scan()
        table = Table(title="Findings")
        table.add_column("Rule", style="cyan")
        table.add_column("Filename", style="cyan")
        table.add_column("Content", style="red")
        for finding in scanner.findings:
            table.add_row(
                "{}\r\n[green]{}[/]".format(finding.match.rule_name, finding.category),
                "{} {}".format(
                    finding.filename, (":cross_mark:" if finding.whiteout else "")
                ),
                finding.obfuscated_content
                if not args.deobfuscated
                else finding.content,
            )

        console = Console()
        console.print(table)


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
