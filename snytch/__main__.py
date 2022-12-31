import json
import sys
import tarfile
from snytch.client import DockerClient

from snytch.image_scanner import SecretsScanner
from snytch.types import Image, Layer


def main():
    image = read_image(sys.argv[1])
    scanner = SecretsScanner(sys.argv[1])
    scanner.scan()


def read_image(name: str) -> Image:
    client = DockerClient()
    file = client.export_image(name)
    if not tarfile.is_tarfile(file):
        raise Exception("Not an image")
    file.seek(0)
    with tarfile.open(fileobj=file) as img:
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
    return Image(manifest["RepoTags"], layers)


def get_layer_history(config: dict, layer_index: int):
    return config["history"][layer_index]


if __name__ == "__main__":
    main()
