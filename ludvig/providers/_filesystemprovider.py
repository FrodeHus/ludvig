import glob
import os
from ._providers import BaseFileProvider


class FileSystemProvider(BaseFileProvider):
    def __init__(self, path) -> None:
        super().__init__()
        self.path = path

    def get_files(self):
        for filename in glob.iglob(os.path.join(self.path, "**/*"), recursive=True):
            if os.path.isdir(filename):
                continue
            with open(filename, "rb") as f:
                yield f, filename
