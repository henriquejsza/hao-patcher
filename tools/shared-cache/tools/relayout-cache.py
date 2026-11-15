#!/usr/bin/env python3
"""Build/verify a scratch-only, identity-preserving 25G241 cache relayout.

No replacement injection, kernel mapping, installation or deployment. The old
UUID is retained solely for the unchanged-image layout experiment. Outputs must
live in work/ and pass the independent verifier before publication.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dyld_rebuild import atlas
from dyld_rebuild.cache import CacheFamily
from dyld_rebuild.exports import require
from dyld_rebuild.relayout import make_plan, write_main
from dyld_rebuild.verify_relayout import verify


def inputs(pins_path):
    spec = importlib.util.spec_from_file_location("provider_audit", ROOT / "tools/audit-providers.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    pins = json.loads(pins_path.read_text())
    require(pins.get("schema") == 1 and pins.get("build") == "25G241" and pins.get("architecture") == "x86_64",
            "unknown relayout input schema/build/architecture")
    expected = {pins["main"] + suffix for suffix in ("", ".01", ".02", ".03", ".04", ".05", ".06", ".map", ".atlas")}
    require(len(pins["files"]) == 9 and {item["path"] for item in pins["files"]} == expected,
            "every cache file and both required sidecars must be pinned")
    for item in pins["files"]:
        audit.verify_input(ROOT, item)
    path = ROOT / pins["main"]
    require(path in [ROOT / item["path"] for item in pins["files"]], "main file not pinned")
    return pins, path


def publish(source, destination):
    # Darwin's atomic exclusive directory rename, so a racing writer cannot have
    # its empty directory replaced. Flag from the SDK's sys/stdio.h RENAME_EXCL.
    require(sys.platform == "darwin", "exclusive publication requires macOS")
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    rename = libc.renamex_np
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(os.fsencode(source), os.fsencode(destination), 4):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def build(pins, source_path, output, growth):
    require(not output.exists() and not output.is_symlink(), "output already exists")
    require(output.resolve().is_relative_to((ROOT / "work").resolve()), "scratch output must be under work/")
    require(output.parent.is_dir(), "output parent does not exist")
    source = CacheFamily(source_path)
    try:
        plan, extension = make_plan(source, growth=growth)
        original_atlas = atlas.read(source_path.with_name(source_path.name + ".atlas"), source.main.data[88:104])
        new_atlas, atlas_segments = atlas.transformed(original_atlas, source, growth,
                                                     plan["new_signature_offset"] + plan["new_signature_size"])
        map_text = atlas.map_text(source_path.with_name(source_path.name + ".map").read_text(),
                                  plan["cutoff"], plan["cutoff"] + growth, source.main.mappings[0].address)
        with tempfile.TemporaryDirectory(prefix=".relayout-stage-", dir=output.parent) as temp:
            stage = Path(temp) / "family"
            stage.mkdir()
            target = stage / source_path.name
            write_main(source, target, plan, extension)
            for file in source.files[1:]:
                dest = stage / file.path.name
                cloned = subprocess.run(["/bin/cp", "-c", str(file.path), str(dest)], capture_output=True)
                if cloned.returncode:
                    shutil.copyfile(file.path, dest)
            atlas.write(stage / (source_path.name + ".atlas"), new_atlas)
            (stage / (source_path.name + ".map")).write_text(map_text)
            candidate = CacheFamily(target)
            try:
                result = verify(source, candidate)
                identities = {file.path.name: {"size": len(file.data), "sha256": hashlib.sha256(file.data).hexdigest()}
                              for file in candidate.files}
            finally:
                candidate.close()
            for suffix in (".map", ".atlas"):
                path = stage / (source_path.name + suffix)
                identities[path.name] = {"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            result.update({"inputs": pins, "outputs": identities, "atlas_segment_offsets_changed": atlas_segments,
                           "source_signature_reemission": "byte-identical complete signature blob",
                           "plan": plan, "runtime_acceptance": "OPEN: no cache loaded; no security settings changed"})
            (stage / "relayout-report.json").write_text(json.dumps(result, indent=2) + "\n")
            publish(stage, output)
        return result
    finally:
        source.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins", type=Path, default=ROOT / "config/relayout-inputs.json")
    parser.add_argument("--growth", type=lambda value: int(value, 0), default=0x40000)
    args = parser.parse_args()
    try:
        pins, source_path = inputs(args.pins)
        if args.action == "build":
            result = build(pins, source_path, args.output, args.growth)
        else:
            source = CacheFamily(source_path)
            try:
                candidate = CacheFamily(args.output / source_path.name)
                try:
                    result = verify(source, candidate)
                finally:
                    candidate.close()
            finally:
                source.close()
        print(json.dumps({k: v for k, v in result.items() if k not in ("inputs", "outputs", "plan")}, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
