import glob
from io import BytesIO
import time
from typing import List
from ._providers import BaseFileProvider
from ._git import GitRepository, ObjectCache, GitObjectType
import os
from knack import log

logger = log.get_logger(__name__)


class GitRepositoryProvider(BaseFileProvider):
    def __init__(
        self,
        path: str,
        commit: str = None,
        fast_scan=False,
        exclusions: List[str] = None,
        max_file_size=10000,
    ) -> None:
        super().__init__(exclusions=exclusions, max_file_size=max_file_size)
        self.path = path
        self.commit = commit
        self.fast_scan = fast_scan

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
            start_time = time.time()
            time_total = 0
            time_commit_avg = 0
            with GitRepository(pack_files) as repo:
                if self.commit:
                    commits = [
                        commit for commit in repo.commits if commit.hash == self.commit
                    ]
                else:
                    commits = repo.commits

                num_commits = len(commits)
                obj_cache = ObjectCache()
                for idx, commit in enumerate(commits, start=1):
                    time_commit = time.time()
                    try:
                        if time.time() - start_time > 300:
                            logger.warn(
                                "scanning is taking a long time... [status: %d / %d commits | %.2f commits/s | est. completed: %d min]",
                                idx,
                                num_commits,
                                time_commit_avg,
                                (((num_commits - idx) / time_commit_avg)) / 60,
                            )
                            start_time = time.time()
                        tree = repo.get_tree(hash=commit.tree_hash)
                        if not tree:
                            logger.warn("failed to read tree %s", commit.tree_hash)
                            continue
                        for leaf in repo.walk_tree(tree, obj_cache=obj_cache):
                            if self.is_excluded(leaf.path):
                                continue
                            content, _, size = repo.get_pack_object(
                                hash=leaf.hash,
                                expected_type=GitObjectType.OBJ_BLOB
                                if self.fast_scan and leaf.is_regular_file()
                                else None,
                            )
                            if not content or size > self.max_file_size:
                                continue
                            with BytesIO(content) as c:
                                yield c, leaf.path, commit.hash
                        time_commit_scan = time.time() - time_commit
                        time_total += time_commit_scan
                        time_commit_avg = idx / time_total
                    except Exception as ex:
                        logger.error(ex)
                        continue
