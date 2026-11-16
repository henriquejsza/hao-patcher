"""Read/write the pinned external atlas through Apple's aa and Python plistlib."""
from pathlib import Path
import plistlib
import subprocess
import tempfile
import uuid
from .exports import require

BASE = "dyld_shared_cache_x86_64"


def read(path, cache_uuid):
    identity = str(uuid.UUID(bytes=cache_uuid)).upper()
    expected = {f"caches/names/{BASE}.plist", f"caches/uuids/{identity}.plist"}
    names = subprocess.check_output(["/usr/bin/aa", "list", "-i", str(path)], text=True).splitlines()
    require(len(names) == 2 and set(names) == expected, "unknown atlas archive members")
    with tempfile.TemporaryDirectory(prefix="atlas-read-") as tmp:
        root = Path(tmp)
        subprocess.run(["/usr/bin/aa", "extract", "-i", str(path), "-d", str(root)], check=True, capture_output=True)
        target = root / f"caches/uuids/{identity}.plist"
        link = root / f"caches/names/{BASE}.plist"
        require(target.is_file() and not target.is_symlink() and link.is_symlink()
                and link.resolve() == target.resolve(), "invalid atlas file/link")
        value = plistlib.loads(target.read_bytes())
    require(set(value) == {"names", "uuids"} and set(value["names"]) == {BASE}
            and set(value["uuids"]) == {identity}, "unknown atlas dictionaries")
    require(value["names"][BASE] == value["uuids"][identity], "atlas UUID/name records disagree")
    return value


def transformed(value, family, growth, new_size):
    """Update main-file layout, leaving all image identities and VM ranges intact."""
    import copy
    value = copy.deepcopy(value)
    cache = value["names"][BASE]
    require(cache["uuid"] == family.main.data[88:104], "atlas UUID mismatch")
    require(len(cache["dscs"]) == len(family.files), "atlas file count mismatch")
    for record, file in zip(cache["dscs"], family.files):
        require(record["name"] == file.path.name and record["uuid"] == file.data[88:104]
                and record["fsze"] == len(file.data), "atlas file identity/size mismatch")
        require(len(record["maps"]) == len(file.mappings), "atlas mapping count mismatch")
        for item, mapping in zip(record["maps"], file.mappings):
            require(item == {"padr": mapping.address, "size": mapping.size, "foff": mapping.offset, "prot": mapping.maximum},
                    "atlas mapping mismatch")
    main = cache["dscs"][0]
    main["fsze"] = new_size
    for i, mapping in enumerate(main["maps"]):
        if i == 0:
            mapping["size"] += growth
        else:
            mapping["foff"] += growth
    require({i["name"]: i["padr"] for i in cache["imgs"]} == dict(family.images), "atlas image inventory mismatch")
    changed = 0
    cutoff = family.main.mappings[0].size
    for image in cache["imgs"]:
        for segment in image["segs"]:
            if not segment["fsze"]:
                continue
            owner, offset = family.locate(segment["padr"], segment["fsze"])
            require(offset == segment["foff"], "atlas segment file offset mismatch")
            if owner is family.main and offset >= cutoff:
                segment["foff"] += growth
                changed += 1
    # Python preserves the shared dictionary object read from this plist. Explicitly
    # set it as well so both atlas lookups remain equivalent if the encoder changes.
    identity = next(iter(value["uuids"]))
    value["uuids"][identity] = cache
    return value, changed


def write(path, value):
    require(not path.exists(), "atlas output exists")
    identity = next(iter(value["uuids"]))
    with tempfile.TemporaryDirectory(prefix="atlas-write-") as tmp:
        root = Path(tmp)
        (root / "caches/uuids").mkdir(parents=True)
        (root / "caches/names").mkdir(parents=True)
        (root / f"caches/uuids/{identity}.plist").write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False))
        (root / f"caches/names/{BASE}.plist").symlink_to(f"../uuids/{identity}.plist")
        # Exclude timestamps/owner/xattrs so the output is deterministic and has
        # only the file payload and link/path/type information needed by the atlas.
        subprocess.run(["/usr/bin/aa", "archive", "-d", str(root), "-o", str(path), "-a", "raw",
                        "-exclude-field", "all", "-include-field", "dat", "-include-type", "fl"],
                       check=True, capture_output=True)


def map_text(original, old_size, new_size, address):
    lines = original.splitlines(keepends=True)
    def first(size):
        return f"mapping  EX {size // (1024 * 1024):4d}MB 0x{address:X} -> 0x{address + size:X}\n"
    require(lines and lines[0] == first(old_size), "unexpected map first mapping")
    lines[0] = first(new_size)
    return "".join(lines)
