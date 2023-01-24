import json
import tarfile
from ludvig.client import DockerClient
from ludvig.rules.loader import load_yara_rules
from ludvig.scanners import ImageScanner
from ludvig.types import Image, Layer, Severity

def scan(repository : str, custom_rules : str = None, severity_level : Severity = Severity.MEDIUM, deobfuscated=False):
    """
    Scans a container image
    :param repository: Container image to scan (ex: myimage:1.1)
    :param custom_rules: Path to any custom YARA rules (need to have .yar extension)
    :param severity_level: Set severity level for reporting
    :param deobfuscated: Returns any secrets found in plaintext. Defaults to False.
    """
    if isinstance(severity_level, str):
        severity_level = Severity[severity_level]
    yara_rules = load_yara_rules(custom=custom_rules)
    with __read_image(repository) as image:
        scanner = ImageScanner(image, yara_rules, severity_level, deobfuscated)
        scanner.scan()
        return scanner.findings
    
def __read_image(name: str) -> Image:
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