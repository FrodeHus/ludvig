import re
from tarfile import TarFile
from typing import List
import yara
from ludvig.utils import get_line_number


class Layer:
    def __init__(self, id: str, created_by: str = None, empty_layer=False) -> None:
        self.id = id
        self.created_by = created_by
        self.empty_layer = empty_layer


class Image:
    def __init__(
        self, repo_tags: List[str], layers: List[Layer], image_archive: TarFile
    ) -> None:
        self.repo_tags = repo_tags
        self.layers = layers
        self.image_archive = image_archive

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.image_archive.close()

class RuleMatch:
    def __init__(self, rule_name : str, category : str = None, tags : List[str] = None) -> None:
        self.rule_name = rule_name
        self.tags = tags
        self.category = category
        
class YaraRuleMatch(RuleMatch):
    def __init__(self, yara : yara.Match) -> None:
        super().__init__(yara.rule, yara.namespace, yara.tags)
        self.__yara_match = yara
    
    def strings(self) -> List[str]:
        strings = []
        for string_match in self.__yara_match.strings:
            strings.append({
                "offset": string_match[0],
                "identifier": string_match[1],
                "plaintext": string_match[2]
            })
        return strings

class Finding:
    def __init__(
        self, category: str, match: RuleMatch, filename: str, whiteout: bool = False
    ) -> None:
        self.category = category
        self.match = match
        self.filename = filename
        self.content = None
        self.whiteout = whiteout


class SecretFinding(Finding):
    def __init__(
        self, rule: RuleMatch, filename: str
    ) -> None:
        super().__init__(rule.category, rule, filename)
        strings = rule.strings()
        self.content = strings[0]["plaintext"].decode("utf-8")
        # matched = secret_match.group("value")
        # location = secret_match.regs[len(secret_match.regs)-1]
        # line_number, line = get_line_number(content, location[0])
        # obfuscation = "*" * len(matched)
        # obfuscation = obfuscation[:7] + '...' if len(obfuscation) > 10 else obfuscation
        # line = line.replace(matched, obfuscation)
        # self.content = "{}: {}".format(line_number + 1, line.lstrip())
