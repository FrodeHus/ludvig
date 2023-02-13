# https://ossf.github.io/osv-schema/


import re
from typing import List


class OSVParseException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


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
        self.__allowed = ["introduced", "fixed", "last_affected", "limit"]
        """
        Defines a package event.
        Can only one of either introduced, fixed, last_affected or limit.
        """
        [(name, value)] = list(kwargs.items())
        assert name in self.__allowed
        setattr(self, name, value)
        self.__validate()

    def __validate(self):
        pass


class OSVRange:
    def __init__(self, type: str, events: List[OSVEvent], repo: str = None) -> None:
        self.type: str = type
        self.repo: str = repo
        self.events: List[OSVEvent] = events
        self.database_specific: str = None
        self.ecosystem_specific: dict = {}
        self.__validate()

    def __validate(self):
        if self.type == "git" and not self.repo:
            raise OSVParseException("repo is required when type is 'git'")
        if (
            not self.events
            or not len([e for e in self.events if hasattr(e, "introduced")]) >= 1
        ):
            raise OSVParseException(
                "events must have atleast one occurence of an 'introduced' event"
            )


class OSVPackage:
    def __init__(self, ecosystem: str, name: str, package_url: str = None) -> None:
        self.ecosystem: str = ecosystem
        self.name: str = name
        self.package_url: str = package_url
        self.__validate()

    def __validate(self):
        valid_ecosystems = [
            "go",
            "npm",
            "oss-fuzz",
            "pypi",
            "rubygems",
            "crates.io",
            "packagist",
            "maven",
            "nuget",
            "linux",
            "debian",
            "alpine",
            "hex",
            "android",
            "github actions",
            "pub",
        ]
        if self.ecosystem.lower() not in valid_ecosystems:
            raise OSVParseException(
                "{} is not a valid ecosystem".format(self.ecosystem)
            )


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
        published: str,
        withdrawn: str,
        summary: str,
        details: str,
        aliases: List[str],
        severity: List[OSVSeverity],
        affected: List[OSVAffected],
        references: List[OSVReference] = [],
        database_specific: dict = {},
        schema_version="1.3.0",
    ) -> None:
        self.schema_version: str = schema_version
        self.id: str = id
        self.modified: str = modified
        self.published: str = published
        self.withdrawn: str = withdrawn
        self.aliases: List[str] = aliases
        self.related: List[str] = []
        self.summary: str = summary
        self.details: str = details
        self.severity: List[OSVSeverity] = severity
        self.affected: List[OSVAffected] = affected
        self.references: List[OSVReference] = references
        self.database_specific: dict = database_specific
        self.__validate()

    def __validate(self):
        valid_id_prefixes = [
            "A-",
            "GO-",
            "OSV-",
            "PYSEC-",
            "RUSTSEC-",
            "GSD-",
            "GHSA-",
            "LBSEC-",
            "DSA-",
            "DLA-",
            "DTSA-",
            "CVE-",
        ]
        if not self.id.startswith(tuple(valid_id_prefixes)):
            raise OSVParseException("not a valid id - {}".format(self.id))

        if not validate_rfc3339_date(self.modified):
            raise OSVParseException("'modified' does not match RFC3339 date format")

        if self.published and not validate_rfc3339_date(self.published):
            raise OSVParseException("'published' does not match RFC3339 date format")

        if self.withdrawn and not validate_rfc3339_date(self.withdrawn):
            raise OSVParseException("'withdrawn' does not match RFC3339 date format")


def validate_rfc3339_date(date_str: str):
    rfc3339 = r"^((?:(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}(?:\.\d+)?))(Z|[\+-]\d{2}:\d{2})?)$"
    if re.match(
        rfc3339,
        date_str,
    ):
        return True
    return False
