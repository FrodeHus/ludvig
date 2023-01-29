import binascii
import codecs
from collections import OrderedDict
import glob
from io import BufferedReader, BytesIO
import struct
from typing import List
from ._providers import BaseFileProvider
import zlib, os
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
            index = self.__read_git_index(os.path.join(repo, "index"))
            if not index:
                return
            obj_path = os.path.join(repo, "objects")

            for (dir_path, _, file_names) in os.walk(obj_path):
                for filename in file_names:
                    f = os.path.join(dir_path, filename)
                    if f.endswith(".idx"):
                        pack_index = self.__read_git_pack_idx(f)
                        for obj in pack_index["objects"]:
                            try:
                                content = self.__decompress_pack_file(
                                    f.replace(".idx", ".pack"), obj["offset"]
                                )
                                if not content:
                                    continue
                                with BytesIO(content) as c:
                                    yield c, obj["name"]
                            except:
                                continue
                    if f.endswith(".pack"):
                        pack_file = self.__read_git_pack(f)
                    if self.is_excluded(f) or os.stat(f).st_size > self.max_file_size:
                        continue
                    with BytesIO(self.__read_object(f)) as f:
                        yield f, filename

    def __read_object(self, path):
        with open(path, "rb") as f:
            result = zlib.decompress(f.read())
            return result

    def __decompress_pack_file(self, pack_file: str, offset: int):
        with open(pack_file, "rb") as f:
            f.seek(offset)
            type = read(f, "B")
            content = None
            if not (type & 0x70) >> 4 in [1, 6]:
                return
            if (type & 0x70) >> 4 == 1:  # OBJ_COMMIT
                obj_len = self.__read_len(f, type)
                content = zlib.decompress(f.read(obj_len))
            elif (type & 0x70) >> 4 == 6:  # OBJ_OFS_DELTA
                obj_len = self.__read_len(f, type)
                byte0 = read(f, "B")
                offset = self.__read_len(f, byte0)
                content = zlib.decompress(f.read(obj_len))
        return content

    def __read_len(self, fin, byte0):

        len_barr = bytearray()
        len_barr.append(byte0 & 0x0F)

        # read the rest of the bytes of the length
        while True:
            byt = struct.unpack("B", fin.read(1))[0]

            if byt & 0x80:  # MSB is 1 we need to reread

                len_barr.append(byt & 0x7F)
            else:
                len_barr.append(byt & 0x7F)
                break

        return int(codecs.encode(bytes(reversed(len_barr)), "hex"), 16)

    def __read_git_pack_idx(self, pack_index_file):
        # docs : https://git-scm.com/docs/pack-format, https://codewords.recurse.com/issues/three/unpacking-git-packfiles
        idx = OrderedDict()
        with open(pack_index_file, "rb") as f:
            signature = f.read(4)
            if signature != b"\xfftOc":
                logger.error("Not a Git pack index file: %s", pack_index_file)
                return
            idx["version"] = read(f, "I")
            fan_out = f.read(255 * 4)
            idx["total_objects"] = read(f, "I")
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

    def __read_git_pack(self, pack_file: str):
        # docs : https://git-scm.com/docs/pack-format, https://codewords.recurse.com/issues/three/unpacking-git-packfiles
        pack = OrderedDict()
        with open(pack_file, "rb") as f:
            signature = f.read(4).decode("ascii")
            if signature != "PACK":
                logger.error("Not a Git pack file: %s", pack_file)
                return
            pack["version"] = read(f, "I")
            num_entries = read(f, "I")
            for n in range(num_entries):
                pass
        return pack

    def __read_git_index(self, index_path: str):
        # docs: https://git-scm.com/docs/index-format
        index = OrderedDict()

        with open(index_path, "rb") as f:
            signature = f.read(4).decode("ascii")
            if signature != "DIRC":
                logger.error("Not a Git index file: %s", index_path)
                return
            index["version"] = read(f, "I")
            index["entries"] = []
            num_entries = read(f, "I")
            for i in range(num_entries):
                try:
                    entry = OrderedDict()
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


def read(f: BufferedReader, format):
    format = "! " + format
    bytes = f.read(struct.calcsize(format))
    return struct.unpack(format, bytes)[0]
