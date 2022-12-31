import os
import tarfile, json, re
from typing import IO, List
from snytch.client import DockerClient
from snytch.rules.types import SecretScanRule
from snytch.types import Image


class SecretsScanner:
    def __init__(self, image: Image) -> None:
        self.image = image
        self.rules = self.__read_rules()

    def scan(self):
        for layer in self.image.layers:
            print("inspecting layer {}:".format(layer.id))
            layer_archive = self.image.image_archive.extractfile(
                "{}/layer.tar".format(layer.id)
            )
            with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                for member in lf.getmembers():
                    found = self.__scan_secrets(lf, member)
                    if found:
                        print(
                            "{} [{}]-> \r\n{}".format(
                                member.name, layer.created_by, found
                            )
                        )

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
            if self.__scan_secret(strings):
                return strings
        except:
            return None

    def __scan_secret(self, content: str) -> bool:
        for rule in self.rules:
            if re.search(rule.pattern, content):
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
