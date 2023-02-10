import glob
import os
from ludvig.vulndb import (
    OSVulnerability,
    OSVSeverity,
    OSVRange,
    OSVAffected,
    OSVEvent,
    OSVPackage,
    OSVReference,
)
import json


def read_repository(path: str):
    """Reads every GitHub advisory in a directory

    Args:
        path (str): Path to the directory containing advisories
    """
    for file in glob.iglob(os.path.join(path, "GHSA*.json"), recursive=True):
        yield read_advisory(os.path.join(path, file))


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

        for r in item["ranges"]:
            events = []
            for e in r["events"]:
                if "introduced" in e:
                    events.append(OSVEvent(introduced=e["introduced"]))
                elif "fixed" in e:
                    events.append(OSVEvent(fixed=e["fixed"]))
                elif "last_affected" in e:
                    events.append(OSVEvent(last_affected=e["fixed"]))
                elif "limit" in e:
                    events.append(OSVEvent(limit=e["limit"]))

            ranges.append(
                OSVRange(
                    r["type"], repo=r["repo"] if "repo" in r else None, events=events
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
        severity=severity,
        affected=affected,
        references=references,
        database_specific=database_specific,
    )
    return osv
