import base64
import os
import tarfile, re
from typing import IO, List
from ludvig.types import Finding, Severity
from ludvig.providers import ContainerProvider
from ._common import BaseScanner
from knack.log import get_logger

logger = get_logger(__name__)


class ImageScanner(BaseScanner):
    def __init__(
        self,
        file_provider: ContainerProvider,
        severity_level: Severity = Severity.MEDIUM,
        deobfuscated=False,
    ) -> None:
        super().__init__(deobfuscated)
        self.file_provider = file_provider
        self.severity_level = severity_level
        self.findings: List[Finding] = []

    def list_whiteout(self):
        whiteouts = []
        for (
            _,
            file_name,
            layer_id,
            layer_created_by,
        ) in self.file_provider.get_files():
            if os.path.basename(file_name).startswith(".wh."):
                whiteouts.append(
                    {
                        "layer": layer_id,
                        "created_by": layer_created_by,
                        "filename": file_name.replace(".wh.", ""),
                    }
                )

        return whiteouts

    def extract_file(self, filename: str, output: str):
        for (
            file,
            file_name,
            _,
            _,
        ) in self.file_provider.get_files():
            if file_name.lower() == filename:
                logger.info("found %s - extracting to %s ...", filename, output)
                with open(output, "wb") as f:
                    f.write(file.file_data.read())
                return

    def scan(self):
        for (
            file,
            file_name,
            _,
            layer_created_by,
        ) in self.file_provider.get_files():
            if os.path.basename(file_name).startswith(".wh."):
                self.__whiteout(file_name, layer_created_by)
            findings = self.scan_file_data(
                file.file_data, file_name, docker_instruction=layer_created_by
            )
            self.register_findings(findings)

    def __whiteout(self, filename: str, layer_created_by: str):
        finding = [
            finding
            for finding in self.findings
            if finding.filename == filename.replace(".wh.", "")
        ]

        for f in finding:
            f.properties["removed_by"] = layer_created_by
            f.properties["whiteout"] = True

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
