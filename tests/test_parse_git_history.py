import os
from unittest import TestCase
from ludvig.providers._gitprovider import GitPackIndex, GitPack


class TestParseGitHistory(TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)

    def test_parse_pack_index(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        self.assertEqual(len(idx["objects"]), idx["total_objects"])
        self.assertEqual(len(idx["objects"]), 5)

    def test_parse_pack(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.pack")
        pack = GitPack(pack_file, idx)
        self.assertEqual(pack.entries["total_objects"], pack.idx["total_objects"])

    def test_parse_commit(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.pack")
        pack = GitPack(pack_file, idx)
        self.assertIn("929a22af97c28bfb4f0c5e9d29303039a3d7829c", pack.commits)
        commit = pack.commits["929a22af97c28bfb4f0c5e9d29303039a3d7829c"]
        self.assertEqual(
            commit["info"]["tree"], "ce0ca7966eeebc9ca709c921ebca0bbfdecaed9b"
        )

    def test_retrieve_object_offset(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        offset = idx.get_offset("085b1ca796dfc5b6d0a87c3e43146c3667e733b1")
        self.assertEqual(offset, 136)

    def test_build_chain(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.pack")
        pack = GitPack(pack_file, idx)
