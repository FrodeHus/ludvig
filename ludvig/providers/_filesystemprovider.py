import glob
import os
from typing import List
from ._providers import BaseFileProvider


class FileSystemProvider(BaseFileProvider):
    def __init__(self, path, exclusions: List[str] = None, max_file_size=10000) -> None:
        super().__init__(exclusions=exclusions, max_file_size=max_file_size)
        self.path = path

    def get_files(self):
        for filename in glob.iglob(os.path.join(self.path, "**/*"), recursive=True):
            if (
                os.path.isdir(filename)
                or self.is_excluded(filename)
                or os.stat(filename).st_size > self.max_file_size
            ):
                continue
            with open(filename, "rb") as f:
                yield f, filename, None
