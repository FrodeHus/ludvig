import json
import tarfile
from ludvig.client import DockerClient
from ludvig.scanners import ImageScanner
from ludvig.types import Image, Layer, Severity


def scan(
    repository: str,
    custom_rules: str = None,
    severity_level: Severity = Severity.MEDIUM,
    deobfuscated=False,
    output_sarif=None,
):
    """
    Scans a container image
    :param repository: Container image to scan (ex: myimage:1.1)
    :param custom_rules: Path to any custom YARA rules (need to have .yar extension)
    :param severity_level: Set severity level for reporting
    :param deobfuscated: Returns any secrets found in plaintext. Defaults to False.
    :param output_sarif: Generates SARIF report if filename is specified.
    """
    if isinstance(severity_level, str):
        severity_level = Severity[severity_level]
    with __read_image(repository) as image:
        scanner = ImageScanner(image, severity_level, deobfuscated, custom_rules)
        scanner.scan()
        if output_sarif:
            from ludvig.outputs import SarifConverter

            report = SarifConverter.from_findings(scanner.findings)
            with open(output_sarif, "w") as r:
                r.write(report)
        return scanner.findings


def list_whiteouts(repository: str):
    """
    Scans a container image for deleted files
    :param repository: Container image to scan
    """
    with __read_image(repository) as image:
        scanner = ImageScanner(image)
        return scanner.list_whiteout()


def extract_file(repository: str, filename: str, output_file: str):
    """
    Extracts a file from the specified container image (even if marked as deleted) - first occurence only
    :param repository: Container image to read from
    :param filename: File to extract (full path)
    :param output_file: Output file
    """
    with __read_image(repository) as image:
        scanner = ImageScanner(image)
        scanner.extract_file(filename, output_file)


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
