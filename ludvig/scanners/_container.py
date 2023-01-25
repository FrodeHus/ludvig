import base64
import os
import tarfile, re
from typing import IO, List
from ludvig.types import Finding, Image, Layer, Severity
from ._common import BaseScanner
from knack.log import get_logger

logger = get_logger(__name__)


class ImageScanner(BaseScanner):
    def __init__(
        self,
        image: Image,
        severity_level: Severity = Severity.MEDIUM,
        deobfuscated=False,
        custom_rules: str = None,
    ) -> None:
        super().__init__(deobfuscated, custom_rules)
        self.image = image
        self.severity_level = severity_level
        self.findings: List[Finding] = []

    def list_whiteout(self):
        whiteouts = []
        for layer in [l for l in self.image.layers if not l.empty_layer]:
            logger.info("layer %s: %s", layer.id, layer.created_by)
            with self.image.image_archive.extractfile(
                "{}/layer.tar".format(layer.id)
            ) as layer_archive:
                with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                    try:
                        for member in lf.getmembers():
                            if os.path.basename(member.name).startswith(".wh."):
                                whiteouts.append(
                                    {
                                        "layer": layer.id,
                                        "created_by": layer.created_by,
                                        "filename": member.name.replace(".wh.", ""),
                                    }
                                )
                    except:
                        logger.error("failed to list files for layer %s", layer.id)

        return whiteouts

    def extract_file(self, filename: str, output: str):
        for layer in [l for l in self.image.layers if not l.empty_layer]:
            with self.image.image_archive.extractfile(
                "{}/layer.tar".format(layer.id)
            ) as layer_archive:
                with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                    for member in lf.getmembers():
                        if member.name.lower() == filename:
                            logger.info(
                                "found %s - extracting to %s ...", filename, output
                            )
                            data = self.__extract_file(lf, member)
                            with open(output, "wb") as f:
                                f.write(data.read())
                            return

    def scan(self):
        for layer in [l for l in self.image.layers if not l.empty_layer]:
            logger.info("layer %s: %s", layer.id, layer.created_by)
            with self.image.image_archive.extractfile(
                "{}/layer.tar".format(layer.id)
            ) as layer_archive:
                with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                    try:
                        for member in lf.getmembers():
                            if os.path.basename(member.name).startswith(".wh."):
                                self.__whiteout(member.name, layer)
                            data = self.__extract_file(lf, member)
                            if not data:
                                continue
                            findings = self.scan_file_data(
                                data, member.name, docker_instruction=layer.created_by
                            )
                            data.close()
                            self.findings.extend(findings)
                    except:
                        logger.error("failed to list files for layer %s", layer.id)

    def __whiteout(self, filename: str, layer: Layer):
        finding = [
            finding
            for finding in self.findings
            if finding.filename == filename.replace(".wh.", "")
        ]

        for f in finding:
            f.properties["removed_by"] = layer.created_by
            f.properties["whiteout"] = True

    def __extract_file(
        self, image: tarfile.TarFile, file: tarfile.TarInfo
    ) -> IO[bytes]:
        if file.isfile():
            return image.extractfile(file)
        return None

    def __scan_environment(self, variables: List[str]) -> Finding:
        pass

    def __decode_content(self, content: str) -> str:
        for match in self.__possible_base64_encoding(content):
            try:
                decoded = base64.b64decode(match.group()).decode("utf-8")
                content = content.replace(match.group(), decoded)
            except UnicodeDecodeError:
                continue
        return content

    def __possible_base64_encoding(self, content: str):
        return re.finditer(
            r"(^|\s+)[\"']?((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2}))[\"']",
            content,
            flags=re.RegexFlag.MULTILINE,
        )
