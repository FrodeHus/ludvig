from typing import List
import os
import fnmatch


class BaseFileProvider:
    def __init__(self, exclusions: List[str] = None) -> None:
        self.exclusions = exclusions or []
        self.__read_ignore_file()

    def get_files(self):
        pass

    def is_excluded(self, filename: str) -> bool:
        for exclude in self.exclusions:
            return fnmatch.fnmatch(filename, exclude)

    def __read_ignore_file(self):
        if os.path.exists(".ludvigignore"):
            with open(".ludvignore", "r") as fp:
                ignore_data = fp.readlines()
                self.exclusions.extend(ignore_data)
