from typing import List
from dateutil.parser import parse
from dataclasses import dataclass, asdict, field


@dataclass
class Package:
    name: str

    @property
    def __dict__(self):
        return asdict(self)


@dataclass
class Advisory:
    id: int
    ext_id: str
    published: str
    package: Package
    ecosystem: str
    summary: str
    details: str
    affected_version: str
    modified: str = field(default=None)
    fixed_version: str = field(default=None)
    aliases: List[str] = field(default=None)
    source: str = field(default=None)

    def __post_init__(self):
        self.id = f"LV{self.id:06}" if self.id is not None else self.id
        if self.modified:
            self.modified = parse(self.modified)
        if self.published:
            self.published = parse(self.published)

    @property
    def __dict__(self):
        return asdict(self)
