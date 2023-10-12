from ludvig.rules import download_rules
from ludvig.config import RuleSetSource, get_config


def download():
    """
    Downloads and compiles the configured rule sets.
    """
    current_config = get_config()
    download_rules(current_config)


def add_repo(name: str, category: str, url: str):
    """
    Adds a custom repository of YARA rules (needs to be in tar-gzipped format)
    """
    
    current_config = get_config()
    current_config.rule_sources.append(RuleSetSource(name, category, url))
    current_config.save()
