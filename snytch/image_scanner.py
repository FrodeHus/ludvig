import tarfile, json
from typing import IO, List

from snytch.client import DockerClient


class SecretsScanner:
    def __init__(self, image: str) -> None:
        self.image = image

    def scan(self, file: tarfile.TarInfo = None):
        keywords = self.__read_keywords()
        if not file:
            docker_client = DockerClient()
            file = docker_client.export_image(self.image)
        if not tarfile.is_tarfile(file):
            raise Exception("Not an image")
        file.seek(0)
        with tarfile.open(fileobj=file) as img:
            for member in img:
                if member.name.endswith(".tar"):
                    path = member.name.split("/")[0]
                    layer_manifest = self.__get_layer_instruction(
                        img, img.getmember("{}/json".format(path))
                    )
                    print("inspecting layer {}:".format(layer_manifest["id"]))
                    self.scan(self.__extract_file(img, member))
                if not member.name.endswith(".tar"):
                    found = self.__scan_secrets(img, member, keywords)
                    if found:
                        print("{} -> \r\n{}".format(member.name, found))

    def __get_layer_instruction(self, image: tarfile.TarFile, layer: tarfile.TarInfo):
        extracted_layer_manifest = self.__extract_file(image, layer)
        return json.loads(extracted_layer_manifest.read().decode("utf-8"))

    def __extract_file(
        self, image: tarfile.TarFile, file: tarfile.TarInfo
    ) -> IO[bytes]:
        return image.extractfile(file)

    def __scan_secrets(
        self, image: tarfile.TarFile, file: tarfile.TarInfo, keywords: List[str]
    ):
        data = self.__extract_file(image, file)
        if not data:
            return None
        try:
            strings = data.read().decode("utf-8")
            for line in strings.splitlines():

                if self.__scan_keywords(line, keywords):
                    return strings
        except:
            return None

    def __scan_keywords(self, line: str, keywords: List[str]) -> bool:
        for keyword in keywords:
            if line.find(keyword) != -1:
                return True
        return False

    def __read_keywords(self) -> List[str]:
        try:
            import importlib.resources as pkg_resources
        except ImportError:
            import importlib_resources as pkg_resources

        from . import (
            rules,
        )

        with pkg_resources.open_text(rules, "keywords") as fp:
            return fp.read().splitlines()
