"""Bounded FileValidationInfo reader for the pinned 25G241 PBL schema only."""
import struct
from .exports import cstring, require, span


def main_validation(data):
    magic, version, length, count, array = struct.unpack("<5I", span(data, 0, 20))
    require((magic, version) == (0x73703464, 0x1bffc401), "unknown PBL set schema")
    require(length == len(data) and count > 0, "invalid PBL set length/count")
    span(data, array, count * 4)
    offset = struct.unpack_from("<I", data, array)[0]
    loader = span(data, offset, length - offset)
    require(struct.unpack("<I", span(loader, 0, 4))[0] == 0x6c347964, "invalid loader magic")
    require(struct.unpack("<H", span(loader, 6, 2))[0] == 0x8000, "not the main executable loader")
    path_offset = struct.unpack("<H", span(loader, 32, 2))[0]
    fvi_offset = struct.unpack("<H", span(loader, 42, 2))[0]
    require(path_offset >= 104 and fvi_offset >= 104, "missing/overlapping PBL validation metadata")
    path, _ = cstring(loader, path_offset)
    fvi = span(loader, fvi_offset, 56)
    require(fvi[52] in (0, 1) and fvi[53] in (0, 1), "invalid FileValidationInfo flags")
    require(fvi[53] == 1, "PBL does not check CDHash")
    return {"path": path, "cdhash": fvi[32:52].hex(),
            "check_cdhash": True, "check_inode_mtime": bool(fvi[52]),
            "set_version": hex(version)}
