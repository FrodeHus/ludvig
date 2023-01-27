from ludvig.rules import download_rules, RuleSetSource
from ludvig import current_config


def download():
    """
    Downloads and compiles the configured rule sets.
    """
    download_rules(current_config.rule_sources, current_config.config_path)
