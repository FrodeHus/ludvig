from typing import Tuple
from ludvig.rules import download_rules
from ludvig.vulndb import VulnDb
import os
from ludvig.config import Config
from knack.log import get_logger
import tarfile
import urllib.request
import tempfile

logger = get_logger(__name__)


def get_line_number(content: str, position: int) -> Tuple[int, str]:
    lines = content.splitlines()
    lower = 0
    upper = len(lines) - 1
    while lower <= upper:
        index = int(lower + (upper - lower) / 2)
        start = content.index(lines[index])
        if position == start:
            return index, lines[index - 1]
        if start > position:
            upper = index - 1
        else:
            lower = index + 1

    return lower - 1, lines[lower - 1]


def create_ludvig_data_pack(config: Config, output_file: str):
    """Creates a compressed .tar.gz file containing the compiled YARA rules and vulnerability database.

    Args:
        config (Config): The current Ludvig configuration
        output_file (str): Name of the .tar.gz file to create
    """
    if not os.path.exists(config.compiled_rules):
        logger.warn("Yara rules not found - downloading...")
        download_rules(config)
    VulnDb.build(config)
    with tarfile.open(output_file, "w:gz") as tarball:
        tarball.add(config.vuln_db_file, arcname=os.path.basename(config.vuln_db_file))
        tarball.add(
            config.compiled_rules, arcname=os.path.basename(config.compiled_rules)
        )


def download_latest_release(config: Config):
    with tempfile.NamedTemporaryFile() as tmp:
        try:
            urllib.request.urlretrieve(config.latest_data_release, tmp.name)
            with tarfile.open(tmp.name, "r:gz") as tarball:
                tarball.extractall(config.config_path)
        except urllib.error.HTTPError as e:
            logger.error("failed to download latest assets: %s", e)
