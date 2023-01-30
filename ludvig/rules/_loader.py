import glob
from tempfile import TemporaryDirectory, TemporaryFile
from typing import IO, List
import yara
import os
from ._definitions import RuleSetSource
import tarfile
import requests
from knack.log import get_logger

logger = get_logger(__name__)


def load_yara_rules(file: str) -> yara.Rules:
    return yara.load(file)


def download_rules(sources: List[RuleSetSource], config_path: str) -> yara.Rules:
    namespaces = {}
    for src in sources:
        set = __download_rule_set(src)
        if not set:
            continue
        ns = src.category.lower()
        if ns in namespaces:
            namespaces[ns] = namespaces[ns] + "\r\n" + set
        else:
            namespaces[ns] = set

    rules = yara.compile(sources=namespaces)
    output_file = os.path.join(config_path, "ludvig.rules")
    rules.save(output_file)


def __download_rule_set(source: RuleSetSource):
    name = source.name
    url = source.url
    logger.debug("downloading %s from %s", name, url)
    try:
        res = requests.get(url)

        with TemporaryFile(suffix=".tar.gz") as f:
            f.write(res.content)
            f.seek(0)
            return __extract_rules(f)
    except Exception as ex:
        logger.error("failed to retrieve rule package %s from %s: %s", name, url, ex)


def __extract_rules(rule_package: IO[bytes]):
    with TemporaryDirectory() as tmp_dir:
        archive = tarfile.open(fileobj=rule_package, mode="r:gz")
        archive.extractall(tmp_dir)
        rule_codes = []

        for file in glob.iglob(os.path.join(tmp_dir, "**/*.yar"), recursive=True):
            full_path = os.path.join(tmp_dir, file)
            with open(full_path, "r") as f:
                rule_code = f.read()
                rule_codes.append(rule_code)

        return "\r\n".join(rule_codes)
