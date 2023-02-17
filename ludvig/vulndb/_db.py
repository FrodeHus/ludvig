import os
import sqlite3
from tempfile import TemporaryDirectory
from typing import List
import uuid
from zipfile import ZipFile
from knack.log import get_logger
import urllib.request
from ._advisory import Advisory, Package
from ludvig.config import Config

logger = get_logger(__name__)


class VulnDb(object):
    __sql_create_advisory_table = """ CREATE TABLE IF NOT EXISTS Advisory (
                                    id integer PRIMARY KEY AUTOINCREMENT,
                                    package_id INTEGER NOT NULL,
                                    modified datetime,
                                    published datetime,
                                    ext_id text NOT NULL COLLATE NOCASE,
                                    ecosystem text NOT NULL COLLATE NOCASE,
                                    summary varchar(200),
                                    details text,
                                    version text NOT NULL,
                                    fixed text,
                                    source varchar(100),
                                    FOREIGN KEY (package_id) REFERENCES Package(id)
                                ); """

    __sql_create_alias_table = """CREATE TABLE IF NOT EXISTS Alias (
                                    id integer PRIMARY KEY AUTOINCREMENT,
                                    advisory_id INTEGER NOT NULL,
                                    alias varchar(200) COLLATE NOCASE,
                                    FOREIGN KEY (advisory_id) REFERENCES Advisory(id)
                                );
    """

    __sql_create_package_table = """CREATE TABLE IF NOT EXISTS Package (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        name text NOT NULL COLLATE NOCASE
    )
    """

    def __init__(self, config: Config, conn: sqlite3.Connection = None) -> None:
        if not conn:
            self.__conn = self.__get_connection(config.vuln_db_file)
        else:
            self.__conn = conn

    @staticmethod
    def ensure(config: Config) -> None:
        if not os.path.exists(config.vuln_db_file):
            logger.warn(
                "No vulnerability database exists - downloading latest assets..."
            )
            from ludvig.utils import download_latest_release

            download_latest_release(config)

    @staticmethod
    def build(config: Config) -> None:
        if os.path.exists(config.vuln_db_file):
            os.remove(config.vuln_db_file)

        for src in config.vulndb_sources:
            with TemporaryDirectory(prefix="ludvig_vulndb_") as p:
                logger.warn(f"Downloading {src.name} from {src.uri}...")
                file = os.path.join(p, f"{uuid.uuid1().hex}.zip")
                urllib.request.urlretrieve(src.uri, file)
                ZipFile(file).extractall(p)
                logger.warn("Building database...")
                with VulnDb(config) as vuln_db:
                    VulnDb.add_osvs(p, vuln_db)

    @staticmethod
    def add_osvs(path: str, vuln_db: "VulnDb") -> None:
        from ludvig.vulndb.ingesters import github_read_repository

        advisories = []
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
                    vuln_db.add_advisories(advisories)
                    advisories.clear()
        vuln_db.add_advisories(advisories)

    def __get_connection(self, db_file: str):

        conn = None
        try:
            conn = sqlite3.connect(db_file)
            if not self.__verify_db_exists(conn.cursor()):
                self.__create_db(conn.cursor())
            return conn
        except sqlite3.Error as e:
            logger.error(e)

    def __verify_db_exists(self, c: sqlite3.Cursor):
        res = c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='advisory';"
        )
        result = res.fetchone()
        if result and "advisories" in result:
            return True
        return False

    def __create_db(self, c: sqlite3.Cursor):
        c.execute(self.__sql_create_package_table)
        c.execute(self.__sql_create_advisory_table)
        c.execute(self.__sql_create_alias_table)

    def add_advisories(self, advisories: List[Advisory]):
        c = self.__conn.cursor()
        for advisory in advisories:
            p = c.execute(
                "SELECT id from package where name = ?", (advisory.package.name,)
            ).fetchone()
            if not p:
                c.execute(
                    "INSERT INTO package (name) VALUES(?)", (advisory.package.name,)
                )
                package_id = c.lastrowid
            else:
                package_id = p[0]

            a = self.query_advisory(
                advisory.package.name,
                advisory.ecosystem,
                advisory.affected_version,
            )
            if not a:
                try:
                    c.execute(
                        """INSERT INTO advisory (package_id, ext_id, modified, published, ecosystem, summary, details, version, fixed, source)
                            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                        (
                            package_id,
                            advisory.ext_id,
                            advisory.modified,
                            advisory.published,
                            advisory.ecosystem,
                            advisory.summary,
                            advisory.details,
                            advisory.affected_version,
                            advisory.fixed_version
                            if hasattr(advisory, "fixed_version")
                            else None,
                            advisory.source,
                        ),
                    )
                    advisory_id = c.lastrowid
                    if advisory.aliases:
                        for alias in advisory.aliases:
                            c.execute(
                                "INSERT INTO Alias (advisory_id, alias) VALUES (?, ?)",
                                (
                                    advisory_id,
                                    alias,
                                ),
                            )
                except Exception as e:
                    logger.error(e)
        self.__conn.commit()

    def query_advisory(
        self,
        package_name: str,
        ecosystem: str,
        version: str,
    ):
        cursor = self.__conn.cursor()

        cursor.execute(
            """
            SELECT a.id, a.ext_id, p.name, a.summary, a.details, a.ecosystem, a.version, a.fixed
            FROM Advisory a
            JOIN Package p ON a.package_id = p.id
            WHERE p.name = ? AND a.ecosystem = ? and (a.version = ? or a.version = '0') COLLATE NOCASE
        """,
            (
                package_name,
                ecosystem,
                version,
            ),
        )
        result = cursor.fetchone()
        if result:
            return [
                Advisory(
                    result[0],
                    result[1],
                    None,
                    Package(result[2]),
                    result[3],
                    None,
                    result[4],
                    result[5],
                    None,
                    result[6],
                )
            ]
        return []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self.__conn.close()


def get_vuln_db(config: Config) -> VulnDb:
    VulnDb.ensure(config)
    return VulnDb(config)
