import base64
import os
import tarfile, json, re
from typing import IO, List, Tuple
from ludvig.rules.types import SecretScanRule
from ludvig.types import Finding, Image, SecretFinding


class SecretsScanner:
    def __init__(self, image: Image) -> None:
        self.image = image
        self.rules = self.__read_rules()
        self.findings: List[Finding] = []

    def scan(self):
        for layer in [l for l in self.image.layers if not l.empty_layer]:
            layer_archive = self.image.image_archive.extractfile(
                "{}/layer.tar".format(layer.id)
            )

            with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                for member in lf.getmembers():
                    if os.path.basename(member.name).startswith(".wh."):
                        self.__whiteout(member.name)

                    for _, finding in enumerate(self.__scan_secrets(lf, member)):
                        if finding:
                            self.findings.append(finding)

    def __whiteout(self, filename: str):
        finding = [
            finding
            for finding in self.findings
            if finding.filename == filename.replace(".wh.", "")
        ]
        if len(finding) == 0:
            return
        finding[0].whiteout = True

    def __extract_file(
        self, image: tarfile.TarFile, file: tarfile.TarInfo
    ) -> IO[bytes]:
        if file.isfile():
            return image.extractfile(file)
        return None

    def __scan_secrets(self, image: tarfile.TarFile, file: tarfile.TarInfo) -> Finding:
        data = self.__extract_file(image, file)

        if not data:
            return None
        try:
            strings = data.read().decode("utf-8")
            for _, (rule, match) in enumerate(self.__scan_secret(strings)):
                if match != None:
                    yield SecretFinding(rule, match, file.name)
        except Exception as ex:
            return None

    def __scan_secret(self, content: str) -> Tuple[bool, SecretScanRule, re.Match[str]]:
        content = self.__decode_content(content)
        for rule in self.rules:
            for match in re.finditer(rule.pattern, content):
                yield rule, match
        yield None, None

    def __decode_content(self, content: str) -> str:
        for match in self.__possible_base64_encoding(content):
            try:
                decoded = base64.b64decode(match.group()).decode("utf-8")
                content = content.replace(match.group(), decoded)
            except UnicodeDecodeError:
                continue
        return content

    def __possible_base64_encoding(self, content: str):
        return re.finditer(r"(^|\s+)[\"']?((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2}))[\"']",
            content, flags=re.RegexFlag.MULTILINE
        )

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
