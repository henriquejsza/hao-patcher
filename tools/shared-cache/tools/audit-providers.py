#!/usr/bin/env python3
"""Audit pinned incoming exports without modifying or loading any Apple binary.

Exit 0: audited incoming references resolve; 2: blockers; 1: malformed/unpinned
input. A successful audit alone does not establish complete dependency closure,
ABI compatibility, a valid cache transformation, or macOS acceptance.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dyld_rebuild.exports import Refusal, read_image, require, resolve


def verify_input(root, item):
    path = root / item["path"]
    require(path.resolve().is_relative_to(root.resolve()), "input escapes repository")
    require(path.stat().st_size == item["size"], f"size mismatch: {item['path']}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    require(digest.hexdigest() == item["sha256"], f"hash mismatch: {item['path']}")
    return path


def patch_uses(text, path):
    """Decode the pinned ipsw listing, retaining every non-self patch and GOT use.

    This is a reader of archived evidence, not a new binary patch-table decoder.
    Shared GOT entries have no image label and must never be dropped as self uses.
    """
    lines = text.splitlines()
    header = re.fullmatch(r"\[PATCHES\] (\S+)\s+\((\d+) symbols\)", lines[0])
    require(header is not None and header[1] == path, "patch-list identity mismatch")
    symbol = None
    count = 0
    rows = []
    for line in lines[1:]:
        if not line.strip():
            continue
        export = re.fullmatch(r"(0x[0-9a-f]+): (\S+)", line)
        if export:
            address, symbol = export.groups()
            count += 1
            continue
        use = re.fullmatch(r"\s+(0x[0-9a-f]+): (PATCH|GOT)\s*(.*)", line)
        require(use is not None and symbol is not None, f"unrecognized patch line: {line}")
        location, kind, client = use.groups()
        if kind == "PATCH" and client == path.rsplit("/", 1)[1]:
            continue
        rows.append({"target": path, "exports": [symbol], "original_address": address,
                     "location": location, "patch_kind": kind, "client_label": client})
    require(count == int(header[2]), "patch export count mismatch")
    return rows


def cache_names(path):
    with path.open("rb") as stream:
        header = stream.read(0x200)
        require(header[:16].rstrip(b"\0") == b"dyld_v1  x86_64", "unexpected cache magic")
        start, count = struct.unpack_from("<II", header, 0x1c0)
        require(count == 3608, "unexpected pinned cache image count")
        stream.seek(start)
        entries = stream.read(32 * count)
        require(len(entries) == 32 * count, "short image array")
        names = set()
        for i in range(count):
            offset = struct.unpack_from("<I", entries, i * 32 + 24)[0]
            stream.seek(offset)
            name = stream.read(4096).split(b"\0", 1)
            require(len(name) == 2, "unterminated cache path")
            names.add(name[0].decode())
        require(len(names) == count, "duplicate pinned cache path")
        return names


def audit(root, pins):
    require(pins.get("schema") == 1, "unknown provider input manifest schema")
    paths = {key: verify_input(root, item) for key, item in pins["inputs"].items()}
    images = {}
    inventory = {}
    install_name_changes = []
    for key in pins["providers"]:
        image = read_image(paths[key].read_bytes())
        target = pins["providers"][key]
        expected_name = pins.get("expected_install_names", {}).get(key, target)
        require(image.install_name == expected_name, f"provider install name: {key}")
        require(target not in images, "duplicate provider path")
        images[target] = image
        if image.install_name != target:
            install_name_changes.append({"path": target, "input_install_name": image.install_name,
                                         "status": "OPEN: canonical cached install name required; input unchanged"})
        inventory[target] = {
            "path": pins["inputs"][key]["path"], "exports": len(image.exports),
            "input_install_name": image.install_name,
            "dependencies": [{"path": d.path, "command": hex(d.command), "reexport": d.reexport}
                             for d in image.dependencies],
        }
    available = cache_names(paths["cache_main"]) | images.keys()
    absent = [{"client": path, "dependency": dep.path, "command": hex(dep.command)}
              for path, image in images.items() for dep in image.dependencies
              if dep.path not in available]
    programs = json.loads(paths["program_binds"].read_text())
    require(programs["entries"] == len(programs["rows"]) == 594, "unexpected program bind count")
    require(not programs["unmatched_exports"], "unmatched original program targets")
    references = [("program_bind", row) for row in programs["rows"]]
    for key, path in pins["patch_lists"].items():
        references += [("cache_patch", row) for row in patch_uses(paths[key].read_text(), path)]
    rows = []
    for origin, row in references:
        require(row["target"] in images and bool(row["exports"]), "unknown reference target")
        results = [resolve(images, row["target"], symbol) for symbol in row["exports"]]
        identities = {(r.get("provider"), r.get("input_offset")) for r in results}
        if all(r["status"] == "resolved" for r in results) and len(identities) == 1:
            result = results[0]
        elif len(results) == 1:
            result = results[0]
        else:
            result = {"status": "ambiguous_original_alias", "candidates": results}
        rows.append({"origin": origin, "reference": row, "resolution": result})
    blockers = [row for row in rows if row["resolution"]["status"] != "resolved"]
    counts = {}
    for path in pins["patch_lists"].values():
        counts[path] = {}
        for origin in ("program_bind", "cache_patch"):
            subset = [r for r in rows if r["origin"] == origin and r["reference"]["target"] == path]
            counts[path][origin] = {
                "references": len(subset),
                "symbols": len({s for r in subset for s in r["reference"]["exports"]}),
                "statuses": dict(Counter(r["resolution"]["status"] for r in subset)),
                "missing_symbols": sorted({s for r in subset if r["resolution"]["status"] != "resolved"
                                           for s in r["reference"]["exports"]}),
            }
    return {
        "result": "BLOCKED" if blockers or absent or install_name_changes else "PASS_INCOMING_EXPORTS_ONLY",
        "classification": "FACT", "pins": pins, "providers": inventory,
        "counts": counts, "dependencies_absent_from_supplied_inputs": absent,
        "install_name_changes_required": install_name_changes,
        "blockers": blockers, "references": rows,
        "open": ["transitive dependency/import closure beyond these providers",
                 "cached/program references outside the recorded patch lists and normal binds",
                 "weak-import, missing-symbol sentinel and ABI semantics",
                 "final relocated offsets and loader IDs; no mutation plan emitted",
                 "ObjC categories/classes, required Swift and other pre-rendered caches",
                 "dyld/kernel/cryptex acceptance on the shipped OCLP security configuration"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pins", type=Path, default=ROOT / "config/provider-inputs.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        pins = json.loads(args.pins.read_text())
        report = audit(ROOT, pins)
        # Do not clobber prior evidence or accept an output path as an input mutation.
        with args.output.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"result": report["result"], "counts": report["counts"],
                          "dependencies_absent_from_supplied_inputs": report["dependencies_absent_from_supplied_inputs"],
                          "install_name_changes_required": report["install_name_changes_required"]}, indent=2))
        return 2 if report["result"] == "BLOCKED" else 0
    except (Refusal, OSError, ValueError, KeyError, struct.error) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
