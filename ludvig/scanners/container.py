import base64
import os
import tarfile, re
from typing import IO, List, Tuple
from ludvig.types import Finding, Image, Layer, SecretFinding, YaraRuleMatch
import yara


class ImageScanner:
    def __init__(self, image: Image, yara_rules: yara.Rules) -> None:
        self.image = image
        self.yara = yara_rules
        self.findings: List[Finding] = []

    def scan(self):
        for layer in [l for l in self.image.layers if not l.empty_layer]:
            with self.image.image_archive.extractfile(
                "{}/layer.tar".format(layer.id)
            ) as layer_archive:

                with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                    for member in lf.getmembers():
                        if os.path.basename(member.name).startswith(".wh."):
                            self.__whiteout(member.name, layer)

                        for _, finding in enumerate(
                            self.__scan_files(lf, member, layer)
                        ):
                            if finding:
                                self.findings.append(finding)

    def __whiteout(self, filename: str, layer: Layer):
        finding = [
            finding
            for finding in self.findings
            if finding.filename == filename.replace(".wh.", "")
        ]

        for f in finding:
            f.whiteout = True
            f.removed_by = layer.created_by

    def __extract_file(
        self, image: tarfile.TarFile, file: tarfile.TarInfo
    ) -> IO[bytes]:
        if file.isfile():
            return image.extractfile(file)
        return None

    def __scan_environment(self, variables: List[str]) -> Finding:
        pass

    def __scan_files(
        self, image: tarfile.TarFile, file: tarfile.TarInfo, layer: Layer = None
    ) -> Finding:
        data = self.__extract_file(image, file)

        if not data:
            return None
        try:
            matches = self.yara.match(data=data.read())
            for match in matches:
                offset = match.strings[0][0]
                prefix_offset = 10 if offset > 10 else offset
                offset = offset - prefix_offset
                data.seek(offset)
                snippet = data.read(len(match.strings[0][2]) + prefix_offset).decode(
                    "utf-8"
                )
                yield SecretFinding(YaraRuleMatch(snippet, match), file.name, layer)
        except Exception as ex:
            return None
        finally:
            data.close()

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
