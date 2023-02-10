from ludvig.vulndb import (
    OSVulnerability,
    OSVSeverity,
    OSVRange,
    OSVAffected,
    OSVEvent,
    OSVPackage,
)
import json


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

    osv = OSVulnerability(
        osv_data["id"], osv_data["modified"], severity=severity, affected=affected
    )
    return osv
