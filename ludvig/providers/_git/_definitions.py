import binascii
import enum
import hashlib
from io import BufferedReader
import os
import struct
from typing import List
import zlib
from knack.log import get_logger

logger = get_logger(__name__)

byte_order_network = "!"
byte_order_little_endian = "<"

# handy docs: https://shafiul.github.io//gitbook/7_the_packfile.html, https://git-scm.com/docs/pack-format, https://codewords.recurse.com/issues/three/unpacking-git-packfiles


class GitObjectType(enum.Enum):
    NOT_SUPPORTED = 0
    OBJ_COMMIT = 1
    OBJ_TREE = 2
    OBJ_BLOB = 3
    OBJ_TAG = 4
    OBJ_OFS_DELTA = 6
    OBJ_REF_DELTA = 7


class GitDelta:
    def __init__(
        self, target_offset: int, target_size: int, source_offset: int, data
    ) -> None:
        self.target_offset = target_offset
        self.target_size = target_size
        self.source_offset = source_offset
        self.data = data

    def has_data(self):
        """
        true if this delta has data to add to the target
        """
        return self.data is not None


def read(f: BufferedReader, format, byte_order="!"):
    format = "{}{}".format(byte_order, format)
    bytes = f.read(struct.calcsize(format))
    return struct.unpack(format, bytes)[0]


class GitPackIndex(dict):
    def __init__(self, idx_file: str):
        idx = self.__read(idx_file)
        super().__init__(idx)

    def get_offset(self, object_hash: str):
        t = self.__find_index(self["objects"], object_hash)
        obj = self["objects"][t]
        if obj:
            return obj["offset"]
        return None

    def __find_index(self, elements: dict, value):
        value = int("0x" + value, 0)
        left, right = 0, len(elements) - 1
        while left <= right:
            middle = (left + right) // 2
            middle_element = int("0x" + elements[middle]["name"], 0)
            if middle_element == value:
                return middle

            if middle_element < value:
                left = middle + 1
            elif middle_element > value:
                right = middle - 1

    def __read(self, filename: str):
        idx = {}
        with open(filename, "rb") as f:
            signature = f.read(4)
            if signature != b"\xfftOc":
                raise Exception("Not a Git pack index file: %s", filename)
            idx["version"] = read(f, "I")
            fan_out_table = {}
            for n in range(256):
                fan_out_table["%0.2X" % n] = read(f, "I")
            idx["total_objects"] = fan_out_table["FF"]
            idx["objects"] = []
            for n in range(idx["total_objects"]):
                object_name = binascii.hexlify(f.read(20)).decode("ascii")
                idx["objects"].append({"name": object_name, "offset": 0})
            for n in range(idx["total_objects"]):
                crc = read(f, "I")
            for n in range(idx["total_objects"]):
                offset = read(f, "I")
                idx["objects"][n]["offset"] = offset
        return idx


class GitPack:
    def __init__(self, filename: str, idx: dict) -> None:
        self.filename = filename
        self.__fp = open(filename, "rb")
        self.idx = idx
        self.commits = self.__get_all_commits()
        self.entries = self.__read_git_pack()
        self.__cache = {}

    def get_offset_by_hash(self, hash: str):
        return self.idx.get_offset(hash)

    def get_commit_by_hash(self, commit_hash: str):
        commit = [c for c in self.commits if c.hash == commit_hash]
        if len(commit):
            return commit[0]
        return None

    def get_pack_object(
        self,
        hash: str = None,
        offset: int = None,
        meta_data_only=False,
        expected_type: GitObjectType = None,
    ):
        if hash:
            offset = self.get_offset_by_hash(hash)
        if not offset:
            return None

        hash_key = hashlib.sha1(str(offset).encode()).hexdigest()
        if hash_key in self.__cache:
            return self.__cache[hash_key]

        self.__fp.seek(offset, 0)
        (obj_type, size) = self.__read_pack_object_header(self.__fp)
        if meta_data_only:
            return (offset, obj_type, size)
        content = None
        if obj_type == GitObjectType.NOT_SUPPORTED:
            return
        if obj_type == GitObjectType.OBJ_COMMIT:
            content = self.__read_compressed_object(self.__fp, size)
            return self.__parse_commit_message(content, hash)
        elif obj_type == GitObjectType.OBJ_BLOB:
            content = self.__read_compressed_object(self.__fp, size)
        elif obj_type == GitObjectType.OBJ_TREE:
            content = self.__read_compressed_object(self.__fp, size)
        elif obj_type == GitObjectType.OBJ_REF_DELTA:
            object_name = binascii.hexlify(self.__fp.read(20)).decode("ascii")
            content = self.get_pack_object(hash=object_name)
        elif obj_type == GitObjectType.OBJ_OFS_DELTA:
            delta_offset = self.__read_delta_offset(self.__fp)
            content = self.__read_compressed_object(self.__fp, size)
            content, obj_type = self.__parse_delta(
                content, delta_offset, offset, expected_type=expected_type
            )
        if len(content) < 10000:
            self.__cache[hash_key] = (content, obj_type, len(content))
        return content, obj_type, len(content)

    def __parse_delta(
        self,
        delta_data,
        base_object_offset: int,
        current_offset: int,
        expected_type: GitObjectType = None,
    ):
        delta_list = self.__parse_delta_instructions(delta_data)
        if expected_type == GitObjectType.OBJ_BLOB:
            crude_delta = "".join([d.data for d in delta_list])
            if len(crude_delta) > 0:
                return crude_delta, expected_type
        base_obj, obj_type, size = self.get_pack_object(
            offset=current_offset - base_object_offset
        )

        if obj_type == GitObjectType.OBJ_OFS_DELTA:
            delta_offset = self.__read_delta_offset(self.__fp)
            content = self.__read_compressed_object(self.__fp, size)
            return self.__parse_delta(
                content, delta_offset, current_offset - base_object_offset
            )
        else:
            assembled_object = self.__apply_delta_list(base_obj, delta_list)
            return assembled_object, obj_type

    def get_all_blob_offsets(self):
        for obj in self.idx["objects"]:
            (offset, obj_type, _) = self.get_pack_object(
                hash=obj["name"], meta_data_only=True
            )
            if obj_type == GitObjectType.OBJ_BLOB:
                yield obj["name"], offset

    def object_exists(self, hash: str):
        return len([obj for obj in self.idx["objects"] if obj["name"] == hash])

    def __search_tree(self, tree: "GitTree", match_hash: str):
        for leaf in tree.leafs:
            if leaf.hash == match_hash:
                return leaf
            if leaf.mode == 40000 or leaf.mode == 160000:
                tree = self.get_pack_object(hash=leaf.hash)
                return self.__search_tree(tree, match_hash)
        return None

    def __apply_delta_list(self, source, delta_list: List[GitDelta] = []):
        if len(delta_list) == 0:
            return source
        deltas_applied = b""
        for delta in delta_list:
            deltas_applied = self.__apply_delta(source, deltas_applied, delta)
        return deltas_applied

    def __apply_delta(self, source, data: bytes, delta: GitDelta):
        if delta.has_data():
            return data + delta.data
        else:
            return (
                data
                + source[delta.source_offset : delta.source_offset + delta.target_size]
            )

    def __get_all_commits(self):
        commits = []
        for obj in self.idx["objects"]:
            self.__fp.seek(obj["offset"])
            (obj_type, size) = self.__read_pack_object_header(self.__fp)
            if obj_type == GitObjectType.OBJ_COMMIT:
                content = self.__read_compressed_object(self.__fp, size)
                commit = self.__parse_commit_message(content, obj["name"])
                commits.append(commit)
        return commits

    def __parse_delta_instructions(self, data):
        i, source_length = self.__msb_size(data)
        i, target_length = self.__msb_size(data, i)
        delta_list = []
        target_bytes = 0
        while i < len(data):
            c = data[i]
            i += 1
            if c & 0x80:  # MSB is set - copy instruction
                cp_off, cp_size = 0, 0
                if c & 0x01:
                    cp_off = data[i]
                    i += 1
                if c & 0x02:
                    cp_off |= data[i] << 8
                    i += 1
                if c & 0x04:
                    cp_off |= data[i] << 16
                    i += 1
                if c & 0x08:
                    cp_off |= data[i] << 24
                    i += 1
                if c & 0x10:
                    cp_size = data[i]
                    i += 1
                if c & 0x20:
                    cp_size |= data[i] << 8
                    i += 1
                if c & 0x40:
                    cp_size |= data[i] << 16
                    i += 1

                if not cp_size:
                    cp_size = 0x10000

                rbound = cp_off + cp_size
                if rbound < cp_size or rbound > source_length:
                    break

                delta = GitDelta(target_bytes, cp_size, cp_off, None)
                delta_list.append(delta)
                target_bytes += cp_size
            elif c:  # insert instruction
                delta = GitDelta(target_bytes, c, 0, data[i : i + c])
                delta_list.append(delta)
                i += c
                target_bytes += c
        return delta_list

    def __msb_size(self, data, offset=0):
        """
        Reads variable-length size from byte array
        """
        size = 0
        i = 0
        l = len(data)
        while i < l:
            c = data[i + offset]
            size |= (c & 0x7F) << i * 7
            i += 1
            if not c & 0x80:
                break
        return i + offset, size

    def __parse_commit_message(self, data, hash: str = None):
        info = {"hash": hash}
        msg = data.decode("utf-8").split("\n")
        for i, line in enumerate(msg):
            if line.startswith("tree"):
                info["tree"] = line.split()[1]
            elif line.startswith("parent"):
                info["parent"] = line.split()[1]
            elif line.startswith("author"):
                info["author"] = " ".join(line.split()[1:-2])
            elif line.startswith("committer"):
                info["comitter"] = " ".join(line.split()[1:-2])
        return GitCommit(
            info["parent"] if "parent" in info else None,
            info["tree"],
            info["author"],
            info["comitter"],
            info["hash"],
        )

    def __read_compressed_object(self, f: BufferedReader, size: int):
        try:
            content = zlib.decompress(f.read(size))
            return content
        except:
            return None

    def __read_pack_object_header(self, f: BufferedReader):
        byte0 = read(f, "B")
        obj_type = self.__get_object_type(byte0)
        size = byte0 & 15  # starting size
        s = 4  # starting bit-shift size
        while byte0 & 0x80:  # MSB is 1 so we keep reading to get full length
            byte0 = read(f, "B")
            size += (byte0 & 0x7F) << s
            s += 7
        size += (byte0 & 0x7F) << s
        return (obj_type, size)

    def __read_delta_offset(self, f: BufferedReader):
        """
        Reads variable-length negative offset value (for finding next ofs_delta)
        """
        byte0 = read(f, "B")
        delta_offset = byte0 & 0x7F
        while byte0 & 0x80:
            byte0 = read(f, "B")
            delta_offset += 1
            delta_offset = (delta_offset << 7) + (byte0 & 0x7F)

        return delta_offset

    def __read_git_pack(self):
        pack = {}
        self.__fp.seek(0)
        signature = self.__fp.read(4).decode("ascii")
        if signature != "PACK":
            raise Exception("Not a Git pack file: %s", self.filename)
        pack["version"] = read(self.__fp, "I")
        num_entries = read(self.__fp, "I")
        pack["total_objects"] = num_entries
        for n in range(num_entries):
            pass
        return pack

    def __get_object_type(self, type: int):
        type_id = (type & 0x70) >> 4
        if not type_id in range(1, 8):
            return GitObjectType.NOT_SUPPORTED
        if type_id == 1:
            return GitObjectType.OBJ_COMMIT
        elif type_id == 2:
            return GitObjectType.OBJ_TREE
        elif type_id == 3:
            return GitObjectType.OBJ_BLOB
        elif type_id == 4:
            return GitObjectType.OBJ_TAG
        elif type_id == 6:
            return GitObjectType.OBJ_OFS_DELTA
        elif type_id == 7:
            return GitObjectType.OBJ_REF_DELTA
        return GitObjectType.NOT_SUPPORTED

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self.__fp:
            self.__fp.close()


class GitTreeItem:
    def __init__(self, path: str, mode: int, hash: str) -> None:
        self.path = path
        self.mode = mode
        self.hash = hash

    def is_regular_file(self):
        if self.mode & 0x8000:
            return True
        return False

    def is_directory(self):
        if self.mode & 0x4000:
            return True
        return False


class GitTree:
    def __init__(self, items=List[GitTreeItem]) -> None:
        self.leafs = items


class GitCommit:
    def __init__(
        self,
        parent_hash: str,
        tree_hash: str,
        author: str,
        committer: str,
        hash: str = None,
    ) -> None:
        self.hash = hash
        self.parent_hash = parent_hash
        self.tree_hash = tree_hash
        self.auth = author
        self.comitter = committer


class GitRepository:
    def __init__(self, pack_files: List[str]) -> None:
        self.__packs: List[GitPack] = []
        self.commits = []
        self.__entries = {}
        total_size = 0

        for pf in pack_files:
            total_size += os.stat(pf + ".pack").st_size / (1024 * 1024)
            idx = GitPackIndex(pf + ".idx")
            pack = GitPack(pf + ".pack", idx)
            self.commits.extend(pack.commits)
            self.__packs.append(pack)
        if total_size > 100:
            logger.warn(
                "Git index is larger than 100 (%dMB) - scanning may be slow [commits: %d]",
                total_size,
                len(self.commits),
            )

    def object_exists(self, hash: str):
        for pack in self.__packs:
            if pack.object_exists(hash):
                return True
        return False

    def get_tree(self, hash: str = None, offset: str = None):
        content, obj_type, _ = self.get_pack_object(hash, offset)
        if obj_type != GitObjectType.OBJ_TREE:
            logger.debug(
                "tree object %s returned %s - nuked from history?",
                hash or offset,
                obj_type.name,
            )
            return None
        return self.__parse_tree(content)

    def get_pack_object(
        self,
        hash: str = None,
        offset: str = None,
        meta_data_only=False,
        expected_type: GitObjectType = None,
    ):
        for pack in self.__packs:
            try:
                found, obj_type, size = pack.get_pack_object(
                    hash=hash,
                    offset=offset,
                    meta_data_only=meta_data_only,
                    expected_type=expected_type,
                )
                if found:
                    return found, obj_type, size
            except TypeError as ex:
                logger.debug("could not retrieve %s - not a valid object?", hash)
                logger.debug(ex)
        return None, GitObjectType.NOT_SUPPORTED, -1

    def walk_tree(
        self, tree: "GitTree", path_prefix="", obj_cache: "ObjectCache" = None
    ):
        files = []
        if not hasattr(tree, "leafs"):
            logger.warn("tree has no leafs")
            return files
        for leaf in tree.leafs:
            if leaf.is_regular_file():
                if obj_cache:
                    added, modified = obj_cache.add(leaf, path_prefix)
                    if not added and not modified:
                        continue
                leaf.path = os.path.join(path_prefix, leaf.path)
                files.append(leaf)
            else:
                next_tree = self.get_tree(hash=leaf.hash)
                if not next_tree:
                    logger.debug(
                        "tree %s [%s] was requested but not found in index - nuked?",
                        leaf.hash,
                        os.path.join(path_prefix, leaf.path),
                    )
                    continue
                files.extend(
                    self.walk_tree(
                        next_tree,
                        os.path.join(path_prefix, leaf.path),
                        obj_cache=obj_cache,
                    )
                )
        return files

    def build_history(self):
        pass

    def __parse_tree(self, content) -> "GitTree":
        tree = []
        i = 0
        while i < len(content):
            try:
                x = content.find(b" ", i)
                if x == -1:
                    i += 1
                    continue
                mode = int(content[i:x], 8)
                i = x + 1
                x = content.find(b"\x00", x)
                path = content[i:x].decode("utf-8")
                i += (x - i) + 1
                x = i + 20
                sha = binascii.hexlify(content[i:x]).decode("ascii")
                i = x
                tree_item = GitTreeItem(path, mode, sha)
                tree.append(tree_item)
            except Exception as ex:
                logger.warn("failed to parse git tree: %s", ex)
                return None
        return GitTree(tree)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        for pack in self.__packs:
            pack.close()


class GitMainIndex(dict):
    def __init__(self, idx_file: str):
        idx = self.__read_git_main_index(idx_file)
        super().__init__(idx)

    def __read_git_main_index(self, index_path: str):
        # docs: https://git-scm.com/docs/index-format
        index = {}

        with open(index_path, "rb") as f:
            signature = f.read(4).decode("ascii")
            if signature != "DIRC":
                raise Exception("Not a Git index file: %s", index_path)

            index["version"] = read(f, "I")
            index["entries"] = []
            num_entries = read(f, "I")
            for i in range(num_entries):
                try:
                    entry = {}
                    entry["entry"] = i + 1
                    entry["ctime_seconds"] = read(f, "I")
                    entry["ctime_nanoseconds"] = read(f, "I")
                    entry["mtime_seconds"] = read(f, "I")
                    entry["mtime_nanoseconds"] = read(f, "I")
                    entry["dev"] = read(f, "I")
                    entry["ino"] = read(f, "I")
                    entry["mode"] = read(f, "I")
                    entry["uid"] = read(f, "I")
                    entry["gid"] = read(f, "I")
                    entry["size"] = read(f, "I")
                    entry["sha1"] = binascii.hexlify(f.read(20)).decode("ascii")
                    entry["flags"] = read(f, "H")
                    file_name_length = entry["flags"] & 0xFFF
                    bytes_read = 62
                    if file_name_length < 0xFFF:
                        entry["name"] = f.read(file_name_length).decode(
                            "utf-8", "replace"
                        )
                        bytes_read += file_name_length
                    else:
                        name = []
                        while True:
                            byte = f.read(1)
                            if byte == "\x00":
                                break
                            name.append(byte)
                        entry["name"] = b"".join(name).decode("utf-8", "replace")
                        bytes_read += 1
                    padlen = (8 - (bytes_read % 8)) or 8
                    _ = f.read(padlen)
                    index["entries"].append(entry)
                except Exception as ex:
                    logger.error(ex)
        return index


class ObjectCache:
    def __init__(self) -> None:
        self.__cache = {}

    def add(self, leaf: GitTreeItem, parent_path: str = None):
        modified_hash = False
        new = False
        if parent_path:
            path = os.path.join(parent_path, leaf.path)
        else:
            path = leaf.path
        if path in self.__cache and self.__cache[path] != leaf.hash:
            new = False
            modified_hash = True
        elif path not in self.__cache:
            new = True
        self.__cache[path] = leaf.hash
        return new, modified_hash
