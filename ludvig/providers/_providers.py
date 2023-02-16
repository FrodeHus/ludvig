import abc
from typing import List
import os
import fnmatch


class BaseFileProvider(abc.ABC):
    def __init__(self, exclusions: List[str] = None, max_file_size=200000) -> None:
        self.exclusions = exclusions or []
        self.__read_ignore_file()
        self.max_file_size = max_file_size

    @abc.abstractmethod
    def get_files(self):
        """Retrieves all files and retrieves them for use with scanners.

        The list is filtered by any pattern defined in `.ludvignore` and configured max file size.
        """
        pass

    def is_excluded(self, filename: str) -> bool:
        for exclude in self.exclusions:
            if fnmatch.fnmatch(filename, exclude):
                return True
        return False

    def __read_ignore_file(self):
        if os.path.exists(".ludvignore"):
            with open(".ludvignore", "r") as fp:
                ignore_data = fp.readlines()
                self.exclusions.extend(ignore_data)
