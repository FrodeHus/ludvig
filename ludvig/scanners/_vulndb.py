from ._common import BaseScanner


class VulnerabilityScanner(BaseScanner):
    def __init__(self, deobfuscated=False) -> None:
        super().__init__(deobfuscated)

    def scan(self):
        pass
