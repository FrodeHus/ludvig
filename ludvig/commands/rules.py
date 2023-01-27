from ludvig.rules import download_rules, RuleSetSource
from ludvig import current_config


def download():
    """
    Downloads and compiles the configured rule sets.
    """
    download_rules(current_config.rule_sources, current_config.config_path)


def add_repo(name: str, category: str, url: str):
    """
    Adds a custom repository of YARA rules (needs to be in tar-gzipped format)
    """
    from ludvig import current_config

    current_config.rule_sources.append(RuleSetSource(name, category, url))
    current_config.save()
