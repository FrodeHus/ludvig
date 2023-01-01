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
        for layer in self.image.layers:
            layer_archive = self.image.image_archive.extractfile(
                "{}/layer.tar".format(layer.id)
            )
            with tarfile.open(fileobj=layer_archive, mode="r") as lf:
                for member in lf.getmembers():
                    if os.path.basename(member.name).startswith(".wh."):
                        self.__whiteout(member.name)

                    finding = self.__scan_secrets(lf, member)
                    if finding:
                        self.findings.append(finding)

    def __whiteout(self, filename: str):
        finding = [
            finding
            for finding in self.findings
            if finding.filename == filename.replace(".wh.", "")
        ][0]
        finding.whiteout = True

    def __extract_file(
        self, image: tarfile.TarFile, file: tarfile.TarInfo
    ) -> IO[bytes]:
        return image.extractfile(file)

    def __scan_secrets(self, image: tarfile.TarFile, file: tarfile.TarInfo) -> Finding:
        data = self.__extract_file(image, file)

        if not data:
            return None
        try:
            strings = data.read().decode("utf-8")
            result, rule, match = self.__scan_secret(strings)
            if result:
                return SecretFinding(rule, match, file.name)
        except Exception as ex:
            return None

    def __scan_secret(self, content: str) -> Tuple[bool, SecretScanRule, re.Match[str]]:
        for rule in self.rules:
            m = re.search(rule.pattern, content)
            if m:
                return True, rule, m
        return False, None, None

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
