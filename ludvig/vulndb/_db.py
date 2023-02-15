import sqlite3
from typing import List
from knack.log import get_logger
from ludvig.vulndb import Advisory, Package

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

    def __init__(self, db_file: str = None) -> None:
        if not db_file:
            from ludvig import Config

            current_config = Config.load()
            db_file = current_config.vuln_db_file
        self.__conn = self.__get_connection(db_file)

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
            SELECT a.ext_id, p.name, a.summary, a.details, a.ecosystem, a.version, a.fixed
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
                    None,
                    Package(result[1]),
                    result[2],
                    None,
                    result[3],
                    result[4],
                    None,
                    result[5],
                )
            ]
        return []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self.__conn.close()
