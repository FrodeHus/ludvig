import json
from typing import IO
from cyclonedx.model.component import Component
from cyclonedx.parser import BaseParser, ParserWarning
from packageurl import PackageURL


class DotnetDepsParser(BaseParser):
    def __init__(self, deps_file: IO[bytes] = None) -> None:
        super.__init__()
        deps = json.load(deps_file)
        for target in deps["targets"]:
            pass
