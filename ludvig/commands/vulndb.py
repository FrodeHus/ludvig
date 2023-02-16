import os
import uuid
from ludvig.vulndb.ingesters import github_read_repository
from knack.log import get_logger
from ludvig.vulndb import VulnDb, Package, Advisory
from ludvig import Config
from tempfile import TemporaryDirectory

logger = get_logger(__name__)


def build():
    """
    Builds the vulnerability database from scratch
    """
    import urllib.request
    from zipfile import ZipFile

    current_config = Config.load()
    if os.path.exists(current_config.vuln_db_file):
        os.remove(current_config.vuln_db_file)

    for src in current_config.vulndb_sources:
        with TemporaryDirectory(prefix="ludvig_vulndb_") as p:
            print(f"Downloading {src.name} from {src.uri}...")
            file = os.path.join(p, f"{uuid.uuid1().hex}.zip")
            urllib.request.urlretrieve(src.uri, file)
            print("Extracting...")
            ZipFile(file).extractall(p)
            print("Adding to database...")
            add_osv_repository(p)


def add_osv_repository(path: str):
    """
    Parses OSV advisories and adds to Ludvig's database
    """
    advisories = []
    with VulnDb() as vulnDb:
        for idx, ghsa in enumerate(github_read_repository(path), start=1):
            for affected in ghsa.affected:
                package = Package(affected.package.name)

                advisory = Advisory(
                    id=None,
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
                    vulnDb.add_advisories(advisories)
                    advisories.clear()
        vulnDb.add_advisories(advisories)
