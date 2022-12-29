import tarfile, json, re
from typing import IO, List
from snytch.client import DockerClient
from snytch.rules.types import SecretScanRule


class SecretsScanner:
    def __init__(self, image: str) -> None:
        self.image = image
        self.rules = self.__read_rules()
        self.__docker_client = DockerClient()

    def scan(self, file: tarfile.TarInfo = None):
        if not file:
            file = self.__docker_client.export_image(self.image)
            history = self.__docker_client.image_history(self.image)
        if not tarfile.is_tarfile(file):
            raise Exception("Not an image")
        file.seek(0)
        with tarfile.open(fileobj=file) as img:
            for member in img:
                if member.name.endswith(".tar"):
                    path = member.name.split("/")[0]
                    layer_manifest = self.__get_layer_manifest(
                        img, img.getmember("{}/json".format(path))
                    )

                    layer_history = self.__get_layer_history(
                        history, layer_manifest["id"]
                    )
                    print("inspecting layer {}:".format(layer_manifest["id"]))
                    self.scan(self.__extract_file(img, member))
                if not member.name.endswith(".tar") or not member.name.endswith(
                    "/json"
                ):
                    found = self.__scan_secrets(img, member)
                    if found:
                        print("{} -> \r\n{}".format(member.name, found))

    def __get_layer_manifest(self, image: tarfile.TarFile, layer: tarfile.TarInfo):
        extracted_layer_manifest = self.__extract_file(image, layer)
        return json.loads(extracted_layer_manifest.read().decode("utf-8"))

    def __extract_file(
        self, image: tarfile.TarFile, file: tarfile.TarInfo
    ) -> IO[bytes]:
        return image.extractfile(file)

    def __scan_secrets(self, image: tarfile.TarFile, file: tarfile.TarInfo):
        data = self.__extract_file(image, file)

        if not data:
            return None
        try:
            strings = data.read().decode("utf-8")
            for line in strings.splitlines():

                if self.__scan_secret(line):
                    return strings
        except:
            return None

    def __scan_secret(self, line: str) -> bool:
        for rule in self.rules:
            if re.search(rule.pattern, line):
                return True
        return False

    def __read_rules(self) -> List[SecretScanRule]:
        try:
            import importlib.resources as pkg_resources
        except ImportError:
            import importlib_resources as pkg_resources

        from . import (
            rules,
        )

        with pkg_resources.open_text(rules, "rules.json") as fp:
            rule_str = fp.read()
            return json.loads(rule_str, object_hook=SecretScanRule.from_json)

    def __get_layer_history(self, image_history: list, layer_id: str):
        for item in image_history:
            if item["Id"] == "sha:{}".format(layer_id):
                return item
        return None

    def __get_instruction_history(self, manifest: dict, history: list):
        pass
