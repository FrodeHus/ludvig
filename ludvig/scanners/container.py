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
                orig_offset = match.strings[0][0]
                sample = self.__read_secret_sample(data, orig_offset, len(match.strings[0][2]))
                yield SecretFinding(YaraRuleMatch(sample, match), file.name, layer)
        except Exception as ex:
            return print(ex)
        finally:
            data.close()
            
    def __read_secret_sample(self, data : bytes, offset : int, match_len : int) -> str:
        orig_offset = offset
        prefix_offset = 10 if orig_offset > 10 else orig_offset
        offset = orig_offset - prefix_offset
        data.seek(offset)
        try:
            sample = data.read(match_len + prefix_offset).decode(
                "utf-8"
            )
        except UnicodeDecodeError as e:
            data.seek(orig_offset)
            sample = data.read(match_len).decode("utf-8")
            # sample = ''.join(format(x, '02x') for x in sample)
        return sample

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
