from dataclasses import dataclass, asdict


@dataclass
class VulnDbSource:
    name: str
    uri: str

    @property
    def __dict__(self):
        return asdict(self)
