import os
from unittest import TestCase
from ludvig.providers._git import GitPackIndex, GitPack, GitRepository


class TestParseGitHistory(TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)

    def test_parse_pack_index(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        self.assertEqual(len(idx["objects"]), idx["total_objects"])
        self.assertEqual(len(idx["objects"]), 11)

    def test_parse_pack(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.pack")
        with GitPack(pack_file, idx) as pack:
            self.assertEqual(pack.entries["total_objects"], pack.idx["total_objects"])

    def test_parse_commit(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.pack")
        with GitPack(pack_file, idx) as pack:
            commit = pack.get_commit_by_hash("04ac220976f58bfc67a64bcb3b30571eace538cf")
            self.assertEqual(
                commit.tree_hash, "ca38fde4b9ebe4001389c96176e253469e2bb0d5"
            )

    def test_retrieve_object_offset(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        offset = idx.get_offset("04ac220976f58bfc67a64bcb3b30571eace538cf")
        self.assertEqual(offset, 12)

    def test_parse_git_tree(self):
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack")
        with GitRepository([pack_file]) as p:
            tree = p.get_tree(hash="b6683c89de7b124d3d268affb4811f4f37cb4c88")
            self.assertEqual(len(tree.leafs), 2)
            self.assertTrue([o.path for o in tree.leafs] == ["README.md", "test"])

    def test_apply_delta(self):
        idx_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.idx")
        idx = GitPackIndex(idx_file)
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack.pack")
        with GitPack(pack_file, idx) as pack:
            content, _, _ = pack.get_pack_object(
                "0d75dd8e0d10925f49d9e3e4f06d70fe17247198"
            )
            self.assertEqual(
                """{\n\t"title": "yaay a title",\n\t"pat": "ghp_123abc1234567890abcdefjiklmnopqrstuv",\n\t"server_access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2R1bW15LnN0dWZmLmNvbS8iLCJpYXQiOjE1MTYyMzkwMjIsIm5iZiI6MTY3MzAzMjExNywiZXhwIjoxNjczMDM2NDIwLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.-cDdFD5abX_VeowZzLSoEL4rEbiVlJYOd01Zhg5Ntrk"\n}\n""",
                content.decode("utf-8"),
            )

    def test_build_history(self):
        pack_file = os.path.join(os.path.dirname(__file__), "fixtures/pack")
        with GitRepository([pack_file]) as p:
            history = p.build_history()
