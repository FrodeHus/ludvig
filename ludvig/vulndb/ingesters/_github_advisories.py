import os
from ludvig.vulndb import (
    OSVulnerability,
    OSVSeverity,
    OSVRange,
    OSVAffected,
    OSVEvent,
    OSVPackage,
    OSVReference,
    OSVParseException,
)
import json
from knack.log import get_logger

logger = get_logger(__name__)


def read_repository(path: str):
    """Reads every GitHub advisory in a directory

    Args:
        path (str): Path to the directory containing advisories
    """
    for root, _, files in os.walk(path):
        for file in files:
            if file.startswith("GHSA-"):
                p = os.path.join(root, file)
                try:
                    yield read_advisory(p)
                except OSVParseException as p:
                    logger.warn(p)


def read_advisory(file: str) -> OSVulnerability:
    with open(file, "r") as f:
        osv_data = json.load(f)
    severity = [
        OSVSeverity(item["type"], item["score"]) for item in osv_data["severity"]
    ]
    affected = []
    ranges = []
    for item in osv_data["affected"]:
        package = OSVPackage(
            item["package"]["ecosystem"],
            item["package"]["name"],
            item["package"]["purl"] if "purl" in item["package"] else None,
        )

        if "ranges" in item:
            for r in item["ranges"]:
                events = []
                for e in r["events"]:
                    if "introduced" in e:
                        events.append(OSVEvent(introduced=e["introduced"]))
                    elif "fixed" in e:
                        events.append(OSVEvent(fixed=e["fixed"]))
                    elif "last_affected" in e:
                        events.append(OSVEvent(last_affected=e["last_affected"]))
                    elif "limit" in e:
                        events.append(OSVEvent(limit=e["limit"]))

                ranges.append(
                    OSVRange(
                        r["type"],
                        repo=r["repo"] if "repo" in r else None,
                        events=events,
                    )
                )
        a = OSVAffected(package=package, ranges=ranges)
        affected.append(a)
    references = []
    if "references" in osv_data:
        for rf in osv_data["references"]:
            references.append(OSVReference(rf["type"], rf["url"]))
    database_specific = (
        osv_data["database_specific"] if "database_specific" in osv_data else {}
    )
    osv = OSVulnerability(
        osv_data["id"],
        osv_data["modified"],
        osv_data["published"] if "published" in osv_data else None,
        osv_data["withdrawn"] if "withdrawn" in osv_data else None,
        summary=osv_data["summary"] if "summary" in osv_data else None,
        details=osv_data["details"] if "details" in osv_data else None,
        aliases=osv_data["aliases"] if "aliases" in osv_data else [],
        severity=severity,
        affected=affected,
        references=references,
        database_specific=database_specific,
    )
    return osv
