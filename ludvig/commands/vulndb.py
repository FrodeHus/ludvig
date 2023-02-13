from ludvig.vulndb.ingesters import github_read_repository
from knack.log import get_logger
from ludvig.vulndb import add_advisories, Package, Advisory

logger = get_logger(__name__)


def add_osv_repository(path: str):
    """
    Parses OSV advisories and adds to Ludvig's database
    """
    advisories = []
    for idx, ghsa in enumerate(github_read_repository(path), start=1):
        for affected in ghsa.affected:
            package = Package(affected.package.name)

            advisory = Advisory(
                ext_id=ghsa.id,
                published=ghsa.published,
                modified=ghsa.modified,
                aliases=ghsa.aliases,
                package=package,
                ecosystem=affected.package.ecosystem,
                summary=ghsa.summary,
                details=ghsa.details,
                affected_version="",
                source="ghsa",
            )
            for r in affected.ranges:
                for e in r.events:
                    if hasattr(e, "introduced"):
                        advisory.affected_version = e.introduced
                    elif hasattr(e, "fixed"):
                        advisory.fixed_version = e.fixed
            if advisory.affected_version:
                advisories.append(advisory)
            if len(advisories) > 100:
                add_advisories(advisories)
                advisories.clear()
        print("count: {}".format(idx))
    add_advisories(advisories)
