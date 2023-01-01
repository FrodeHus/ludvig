import json
import sys
import tarfile
from ludvig.client import DockerClient
from ludvig.image_scanner import SecretsScanner
from ludvig.types import Image, Layer
from rich.table import Table
from rich.console import Console


def main():
    with read_image(sys.argv[1]) as image:
        scanner = SecretsScanner(image)
        scanner.scan()
        table = Table(title="Findings")
        table.add_column("Category", style="cyan")
        table.add_column("Rule", style="cyan")
        table.add_column("Filename", style="cyan")
        table.add_column("Content")
        for finding in scanner.findings:
            table.add_row(
                finding.category,
                finding.rule.name,
                "{} {}".format(
                    finding.filename, ("[red](deleted)[/]" if finding.whiteout else "")
                ),
                finding.content,
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
