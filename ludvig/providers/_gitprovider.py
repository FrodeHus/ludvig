import glob
from io import BytesIO
from typing import List
from ._providers import BaseFileProvider
import zlib, os


class GitRepositoryProvider(BaseFileProvider):
    def __init__(
        self, path: str, exclusions: List[str] = None, max_file_size=10000
    ) -> None:
        super().__init__(exclusions=exclusions, max_file_size=max_file_size)
        self.path = path

    def get_files(self):
        repos = glob.iglob(os.path.join(self.path, "**/.git"), recursive=True)
        for repo in repos:
            obj_path = os.path.join(repo, "objects")
            for (dir_path, _, file_names) in os.walk(obj_path):
                for filename in file_names:
                    f = os.path.join(dir_path, filename)
                    if self.is_excluded(f) or os.stat(f).st_size > self.max_file_size:
                        continue
                    with BytesIO(self.__read_object(f)) as f:
                        yield f, filename

    def __read_object(self, path):
        with open(path, "rb") as f:
            result = zlib.decompress(f.read())
            return result

    def __read_git_index(self, index: str):
        pass
