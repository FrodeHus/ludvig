import glob
from io import BytesIO
from typing import List
from ._providers import BaseFileProvider
from ._git import GitPackIndex, GitPack, GitMainIndex
import os
from knack import log

logger = log.get_logger(__name__)


class GitRepositoryProvider(BaseFileProvider):
    def __init__(
        self, path: str, exclusions: List[str] = None, max_file_size=10000
    ) -> None:
        super().__init__(exclusions=exclusions, max_file_size=max_file_size)
        self.path = path

    def get_files(self):
        repos = glob.iglob(os.path.join(self.path, "**/.git"), recursive=True)
        for repo in repos:
            index = GitMainIndex(os.path.join(repo, "index"))
            if not index:
                return
            obj_path = os.path.join(repo, "objects")

            for (dir_path, _, file_names) in os.walk(obj_path):
                for filename in file_names:
                    f = os.path.join(dir_path, filename)
                    if f.endswith(".idx"):
                        pack_idx = GitPackIndex(f)
                        pack = GitPack(f.replace(".idx", ".pack"), pack_idx)
                        for commit_sha in pack.commits:
                            try:
                                commit = pack.commits[commit_sha]
                                tree_object_name = commit.tree_hash
                                tree_offset = [
                                    o["offset"]
                                    for o in pack_idx["objects"]
                                    if o["name"] == tree_object_name
                                ][0]
                                content = pack.get_pack_object(tree_offset)

                            except:
                                continue
                        for obj in pack.blobs:
                            try:
                                content = pack.get_pack_object(
                                    pack.blobs[obj]["offset"]
                                )
                                if not content:
                                    continue
                                with BytesIO(content) as c:
                                    yield c, obj
                            except Exception as ex:
                                logger.error(ex)
                                continue
                    # if f.endswith(".pack"):
                    #     pack_file = self.__read_git_pack(f)
                    # if self.is_excluded(f) or os.stat(f).st_size > self.max_file_size:
                    #     continue
                    # with BytesIO(self.__read_object(f)) as f:
                    #     yield f, filename
