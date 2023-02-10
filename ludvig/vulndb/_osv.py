# https://ossf.github.io/osv-schema/


from typing import List


class OSVSeverity:
    def __init__(self, type: str, score: str) -> None:
        self.type: str = type
        self.score: str = score


class OSVReference:
    def __init__(self, type: str, url: str) -> None:
        self.type: str = type
        self.url: str = url


class OSVEvent:
    def __init__(self, **kwargs) -> None:
        """
        Defines a package event.
        Can only one of either introduced, fixed, last_affected or limit.
        """
        [(name, value)] = list(kwargs.items())
        assert name in ["introduced", "fixed", "last_affected", "limit"]
        setattr(self, name, value)


class OSVRange:
    def __init__(
        self, type: str, repo: str = None, events: List[OSVEvent] = []
    ) -> None:
        self.type: str = type
        self.repo: str = repo
        self.events: List[OSVEvent] = events
        self.database_specific: str = None
        self.ecosystem_specific: dict = {}


class OSVPackage:
    def __init__(self, ecosystem: str, name: str, package_url: str = None) -> None:
        self.ecosystem: str = ecosystem
        self.name: str = name
        self.package_url: str = package_url


class OSVAffected:
    def __init__(
        self, package: OSVPackage, ranges: List[OSVRange], versions: List[str] = None
    ) -> None:
        self.package: OSVPackage = package
        self.ranges: List[OSVRange] = ranges
        self.versions: List[str] = versions


class OSVulnerability:
    def __init__(
        self,
        id: str,
        modified: str,
        severity: List[OSVSeverity],
        affected: List[OSVAffected],
        schema_version="1.3.0",
    ) -> None:
        self.schema_version: str = schema_version
        self.id: str = id
        self.modified: str = modified
        self.published: str = None
        self.withdrawn: str = None
        self.aliases: List[str] = []
        self.related: List[str] = []
        self.summary: str = None
        self.details: str = None
        self.severity: List[OSVSeverity] = severity
        self.affected: List[OSVAffected] = affected
        self.references: List[OSVReference] = []
        self.database_specific: dict = {}
