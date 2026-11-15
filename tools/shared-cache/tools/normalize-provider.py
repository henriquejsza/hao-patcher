#!/usr/bin/env python3
"""Emit a pinned LibSystemShim cache-builder input with a canonical install name.

The original signature blob is retained unreferenced after deliberate removal of
LC_CODE_SIGNATURE, matching dyld cache adjustment. This command never
signs, installs, maps or executes the output. All outputs stay under work/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dyld_rebuild.exports import read_image, require
from dyld_rebuild.provider_identity import inspect, normalize, signature_pages, verify_normalized

BUILDER_SOURCES = {
    "research/astra-cache-builder-gates/dyld-1378/cache_builder/NewAdjustDylibSegments.cpp":
        "40879120e266978916e61ee3a533bca8f68074c78271143f1b384c559ed63c57",
    "research/astra-cache-builder-gates/dyld-1378/cache_builder/NewSharedCacheBuilder.cpp":
        "58d1f19d122c16a04b04f27fb7336cb41afc9dfa5ed5cb28c22a93fc9d6d48c5",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pinned(item):
    path = (ROOT / item["path"]).resolve()
    require(path.is_relative_to(ROOT / "inputs"), "input escapes inputs directory")
    data = path.read_bytes()
    require(len(data) == item["size"] and digest(data) == item["sha256"],
            f"pinned input drift: {item['path']}")
    return path, data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--remove-signature-command", action="store_true", required=True,
                        help="explicit cache-builder-only mode; preserves original signature blob bytes unreferenced")
    args = parser.parse_args()
    destination = args.output_dir.resolve()
    require(destination.is_relative_to(ROOT / "work") and destination != ROOT / "work",
            "output must be a fresh directory under work/")
    require(not destination.exists(), "output directory already exists")
    pinbytes = (ROOT / "config/provider-inputs.json").read_bytes()
    pins = json.loads(pinbytes)
    require(pins["schema"] == 1, "unsupported provider pin schema")
    for path, expected_hash in BUILDER_SOURCES.items():
        require(digest((ROOT / path).read_bytes()) == expected_hash, "pinned builder source drift")
    key = "LibSystemShim.dylib"
    source, data = pinned(pins["inputs"][key])
    canonical = pins["providers"][key]
    output, plan = normalize(data, pins["expected_install_names"][key], canonical,
                             remove_signature_command=args.remove_signature_command)
    independent_verification = verify_normalized(
        data, output, pins["expected_install_names"][key], canonical, removed_signature=True)
    old, new = read_image(data), read_image(output)
    require(old.dependencies == new.dependencies and old.exports == new.exports,
            "provider dependencies or exports changed")
    before_signature = signature_pages(data)
    after_signature = signature_pages(output, original_signature_range=inspect(data)["signature"])
    require(before_signature["mismatching_code_slots"] == [], "source code pages already invalid")
    require(after_signature["mismatching_code_slots"] == [0], "unexpected changed signed pages")
    require(before_signature["signature_sha256"] == after_signature["signature_sha256"],
            "embedded original signature changed")
    clients = []
    for client in pins["providers"]:
        path, contents = pinned(pins["inputs"][client])
        image = read_image(contents)
        for ordinal, dependency in enumerate(image.dependencies, 1):
            if "LibSystemShim" in dependency.path:
                require(dependency.path == canonical, "client uses a noncanonical shim alias")
                clients.append({"key": client, "input": pins["inputs"][client],
                                "ordinal": ordinal, "command": hex(dependency.command),
                                "path": dependency.path})
    destination.mkdir(parents=True, exist_ok=False)
    candidate = destination / key
    with candidate.open("xb") as stream:
        stream.write(output)
    observations = []
    dyld_outputs = []
    for path in (source, candidate):
        for tool, options in (("dyld_info", ["-arch", "x86_64", "-exports", "-dependents", "-fixups"]),
                              ("otool", ["-l"]),
                              ("codesign", ["-dvvv", "--arch", "x86_64"]),
                              ("codesign", ["--verify", "--strict", "--verbose=4"])):
            executable = Path(subprocess.check_output(["xcrun", "--find", tool], text=True).strip())
            run = subprocess.run([str(executable), *options, str(path)], capture_output=True, text=True)
            observations.append({"input": "source" if path == source else "normalized",
                                 "tool": str(executable), "tool_sha256": digest(executable.read_bytes()),
                                 "options": options, "exit": run.returncode,
                                 "stdout": run.stdout, "stderr": run.stderr})
            if tool == "dyld_info":
                require(run.returncode == 0 and not run.stderr, "Apple dyld_info rejected input")
                dyld_outputs.append(run.stdout.replace(str(path), "INPUT"))
            elif tool == "otool":
                require(run.returncode == 0 and not run.stderr, "Apple otool rejected input")
    require(dyld_outputs[0] == dyld_outputs[1], "Apple exports/dependencies/fixups changed")
    report = {"classification": "FACT", "purpose": "cache-builder input only",
              "config_sha256": digest(pinbytes), "builder_source_pins": BUILDER_SOURCES,
              "input": pins["inputs"][key],
              "output": {"path": str(candidate.relative_to(ROOT)), "size": len(output),
                         "sha256": digest(output)},
              "plan": plan, "independent_verification": independent_verification,
              "source_signature_pages": before_signature,
              "output_signature_pages": after_signature,
              "exports_and_offsets_preserved": len(old.exports),
              "dependency_ordinals_preserved": True,
              "chained_fixup_payload_unchanged": True,
              "apple_dyld_info_exports_dependents_fixups_unchanged": True,
              "pinned_provider_clients": clients,
              "signature_status": "LC_CODE_SIGNATURE removed; original blob bytes retained unreferenced; page 0 invalidated; not a runtime artifact or trust proof",
              "open": ["Final cache signing and target acceptance under unchanged shipped baseline",
                       "Client completeness beyond the ten pinned providers and selected daemon"],
              "apple_observations": observations}
    with (destination / "normalization.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"FACT: normalized {key} using {plan['command_growth']} bytes of header padding; LC_CODE_SIGNATURE removed for cache-builder input")


if __name__ == "__main__":
    main()
