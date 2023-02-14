from ._common import BaseScanner


class SecretScanner(BaseScanner):
    def __init__(self, deobfuscated=False) -> None:
        super().__init__(deobfuscated)
