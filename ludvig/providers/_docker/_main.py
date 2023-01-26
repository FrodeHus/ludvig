import json
import tarfile
from ._definitions import Image, Layer
from ._client import DockerClient


def read_local_docker_image(repository: str) -> Image:
    client = DockerClient()
    file = client.export_image(repository)
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
        layer_history = __get_layer_history(file_layers, idx + 1)
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


def __get_layer_history(config: dict, layer_index: int):
    return config[layer_index - 1]
