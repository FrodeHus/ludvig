from typing import List
from dateutil.parser import parse


class Package:
    def __init__(self, name: str) -> None:
        self.name = name


class Advisory:
    def __init__(
        self,
        ext_id: str,
        published: str,
        package: Package,
        ecosystem: str,
        summary: str,
        details: str,
        affected_version: str,
        modified: str = None,
        fixed_version: str = None,
        aliases: List[str] = None,
    ) -> None:
        self.ext_id = ext_id
        if modified:
            self.modified = parse(modified)
        if published:
            self.published = parse(published)
        self.package = package
        self.ecosystem = ecosystem
        self.summary = summary
        self.details = details
        self.affected_version = affected_version
        self.fixed_version = fixed_version
        self.aliases = aliases
