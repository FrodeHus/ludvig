import glob
from io import BytesIO
from typing import List
from ._providers import BaseFileProvider
from ._git import GitRepository
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
            pack_path = os.path.join(repo, "objects")
            pack_files = []
            for file in glob.iglob(
                os.path.join(pack_path, "**/pack-*.pack"), recursive=True
            ):
                pack_name = file[:-5]
                pack_files.append(pack_name)
            with GitRepository(pack_files) as repo:
                for commit in repo.commits:
                    try:
                        tree = repo.get_tree(hash=commit.tree_hash)
                        if not tree:
                            logger.warn("failed to read tree %s", commit.tree_hash)
                            continue
                        for leaf in repo.walk_tree(tree):
                            if self.is_excluded(leaf.path):
                                continue
                            content, _, size = repo.get_pack_object(hash=leaf.hash)
                            if not content or size > self.max_file_size:
                                continue
                            with BytesIO(content) as c:
                                yield c, leaf.path, commit.hash
                    except Exception as ex:
                        logger.error(ex)
                        continue
