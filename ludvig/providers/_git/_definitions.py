import binascii
import enum
from io import BufferedReader
import struct
from typing import List
import zlib
from knack import log

logger = log.get_logger(__name__)

byte_order_network = "!"
byte_order_little_endian = "<"


class GitObjectType(enum.Enum):
    NOT_SUPPORTED = 0
    OBJ_COMMIT = 1
    OBJ_TREE = 2
    OBJ_BLOB = 3
    OBJ_TAG = 4
    OBJ_OFS_DELTA = 6
    OBJ_REF_DELTA = 7


def read(f: BufferedReader, format, byte_order="!"):
    format = "{}{}".format(byte_order, format)
    bytes = f.read(struct.calcsize(format))
    return struct.unpack(format, bytes)[0]


class GitPackIndex(dict):
    def __init__(self, idx_file: str):
        idx = self.__read(idx_file)
        super().__init__(idx)

    def get_offset(self, object_hash: str):
        object = [o for o in self["objects"] if o["name"] == object_hash]
        if len(object) > 0:
            return object[0]["offset"]

    def __read(self, filename: str):
        # docs : https://git-scm.com/docs/pack-format, https://codewords.recurse.com/issues/three/unpacking-git-packfiles
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
        self.idx = idx
        (commits, blobs) = self.__filter_objects_by_type()
        self.commits = commits
        self.blobs = blobs
        self.entries = self.__read_git_pack()

    def get_pack_object(self, offset: int):
        with open(self.filename, "rb") as f:
            f.seek(offset)
            (obj_type, size) = self.__read_pack_object_header(f)
            content = None
            object_name = [
                o["name"] for o in self.idx["objects"] if o["offset"] == offset
            ][0]
            if obj_type == GitObjectType.NOT_SUPPORTED:
                return
            if obj_type == GitObjectType.OBJ_COMMIT:
                content = self.__read_compressed_object(f, size)
                content = self.__parse_commit_message(content)
            elif obj_type == GitObjectType.OBJ_BLOB:
                content = self.__read_compressed_object(f, size)
            elif obj_type == GitObjectType.OBJ_TREE:
                content = self.__read_compressed_object(f, size)
                return self.__parse_tree(content)
            elif obj_type == GitObjectType.OBJ_REF_DELTA:
                (obj_type, size) = self.__read_pack_object_header(f)
                object_name = binascii.hexlify(f.read(20)).decode("ascii")
                content = self.__read_compressed_object(f, size)
            elif obj_type == GitObjectType.OBJ_OFS_DELTA:
                delta_offset = self.__read_msb(f)
                content = self.__read_compressed_object(f, size)
                # delta_offset = read_len(f, byte0)
                obj_name = [
                    o
                    for o in self.idx["objects"]
                    if o["offset"] == (offset - delta_offset)
                ]
                parent_object_name = obj_name["name"] if "name" in obj_name else None
                d = self.__get_ofs_delta(f, offset, delta_offset)
            return content

    def __parse_tree(self, content) -> "GitTree":
        tree = []
        i = 0
        while i < len(content):
            x = content.find(b" ", i)
            if x == -1:
                i += 1
                continue
            mode = content[i:x]
            i = x + 1
            x = content.find(b"\x00", x)
            path = content[i:x].decode("utf-8")
            i += (x - i) + 1
            x = i + 20
            sha = binascii.hexlify(content[i:x]).decode("ascii")
            i = x
            tree_item = GitTreeItem(path, mode, sha)
            tree.append(tree_item)
        return GitTree(tree)

    def __filter_objects_by_type(self):
        commits = {}
        blobs = {}
        with open(self.filename, "rb") as f:
            for obj in self.idx["objects"]:
                f.seek(obj["offset"])
                (obj_type, size) = self.__read_pack_object_header(f)
                if obj_type == GitObjectType.OBJ_BLOB:
                    blobs[obj["name"]] = {"offset": obj["offset"], "deltas": []}
                elif obj_type == GitObjectType.OBJ_COMMIT:
                    content = self.__read_compressed_object(f, size)
                    commit = self.__parse_commit_message(content)
                    commits[obj["name"]] = commit
        return (commits, blobs)

    def __get_ofs_delta(self, f: BufferedReader, initial_offset: int, offset: int):
        f.seek(initial_offset - offset)
        (obj_type, size) = self.__read_pack_object_header(f)
        if obj_type not in [GitObjectType.OBJ_BLOB, GitObjectType.OBJ_OFS_DELTA]:
            return None
        delta_offset = self.__read_msb(f)
        content = self.__read_compressed_object(f, size)
        self.__parse_delta_instructions(content)
        return None

    def __parse_delta_instructions(self, data):
        i, source_length = self.__msb_size(data)
        i, target_length = self.__msb_size(data, i)
        c = data[0]
        if c & 0x80:
            instr = "copy"
        else:
            instr = "insert"

    def __msb_size(self, data, offset=0):
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

    def __parse_commit_message(self, data):
        info = {}
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

    def __read_msb(self, f: BufferedReader):
        size = 0
        byte0 = read(f, "B")
        while byte0 & 0x80:
            size += (byte0 & 0x7F) << 7
            byte0 = read(f, "B")

        return size

    def __read_git_pack(self):
        # docs : https://git-scm.com/docs/pack-format, https://codewords.recurse.com/issues/three/unpacking-git-packfiles
        pack = {}
        with open(self.filename, "rb") as f:
            signature = f.read(4).decode("ascii")
            if signature != "PACK":
                raise Exception("Not a Git pack file: %s", self.filename)
            pack["version"] = read(f, "I")
            num_entries = read(f, "I")
            pack["total_objects"] = num_entries
            for n in range(num_entries):
                pass
        return pack

    def __get_object_type(self, type: int):
        type_id = (type & 0x70) >> 4
        if not type_id in range(1, 7):
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


class GitTreeItem:
    def __init__(self, path: str, mode: int, hash: str) -> None:
        self.path = path
        self.mode = mode
        self.hash = hash


class GitTree:
    def __init__(self, items=List[GitTreeItem]) -> None:
        self.leafs = items


class GitCommit:
    def __init__(
        self, parent_hash: str, tree_hash: str, author: str, committer: str
    ) -> None:
        self.parent_hash = parent_hash
        self.tree_hash = tree_hash
        self.auth = author
        self.comitter = committer


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
