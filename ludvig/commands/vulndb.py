from knack.log import get_logger
from ludvig.vulndb import VulnDb
from ludvig.config import get_config

logger = get_logger(__name__)


def build():
    """
    Builds the vulnerability database from scratch
    """
    current_config = get_config()
    VulnDb.build(current_config)
