"""prespecialization.py: keep Swift prespecialized metadata on in every process of the image.

libswiftCore turns prespecialized metadata off process-wide when `_dyld_shared_cache_some_image_overridden()` is
true. On this image it always is: dyld scans the disk for roots (golden-gate-dyld-internal), and files sit at cache
install paths (OCLP's Metal and Wi-Fi libraries, this recipe's CoreWiFi compat library, Apple's own
libsystem_{kernel,platform,pthread}). The x86_64 cache edits in prespecialization-26B131.json, made by the shared-cache
generator (`make prespecialization-overrides`), do two things:
- main cache: the two calls that read the switch (libPrespecializedImageLoaded and the LibPrespecializedState setup)
  become `xor eax, eax`, so the switch reads false;
- .06: every descriptor-map slot of LibPrespecializedData whose descriptor lies in an overridden image is nulled,
  with its chain delta kept. A null slot reads as empty, so those names take the runtime's ordinary path and never
  return the cache copy's descriptor for a library the process loads from disk.
The third reader, the conformance-block callback, stays: dyld's conformance table is invalid for an overridden image
with __swift5_proto.

The edits are right only for the set of overridden images they were made for. gate() refuses an image whose set
differs: the generator's gate showed 0 of 2,762 Apple entries and 0 of 1,282 catalog keys referencing an image of that set,
and a changed set changes the descriptor slots to drop.

    python3.14 -I prespecialization.py plan CACHE_DIR          print the planned edits per cache file
    python3.14 -I prespecialization.py gate SYSTEM CACHE_DIR   check SYSTEM's overridden set against the recipe's
"""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import swift_refs  # noqa: E402

DATA = Path(__file__).with_name('prespecialization-26B131.json')
UUID_AT = 0x58   # dyld_cache_header.uuid
# dyld itself is in the image list but is never loaded from the cache, so its file does not count.
NOT_LOADED = frozenset({'/usr/lib/dyld'})
REGENERATE = ('the shared-cache generator: make prespecialization-overrides CACHE_MAIN --overridden LIST '
              '--output RECIPE.json, then src/prespecialization-26B131.json and edits/cache-*.json')


def load():
    return json.loads(DATA.read_text())


def cache_uuid(directory):
    with (Path(directory)/'dyld_shared_cache_x86_64').open('rb') as stream:
        stream.seek(UUID_AT)
        return stream.read(16).hex().upper()


def plan_cache_family(directory, data=None):
    """{cache file path: [(offset, before, after, reason)]}: the recipe's edits, after checking the cache's UUID and the
    bytes at every site. Refuses another cache."""
    data = data or load()
    directory = Path(directory)
    found = cache_uuid(directory)
    if found != data['cache_uuid']:
        raise ValueError(f'prespecialization: cache UUID {found}, the edits are for {data["cache_uuid"]}')
    plan = {}
    for name, entry in sorted(data['files'].items()):
        path = directory/name
        changes = []
        with path.open('rb') as stream:
            for e in entry['edits']:
                before, after = bytes.fromhex(e['before']), bytes.fromhex(e['after'])
                if len(before) != len(after) or before == after:
                    raise ValueError(f'prespecialization: {name} {e["at"]:#x}: malformed edit')
                stream.seek(e['at'])
                if stream.read(len(before)) != before:
                    raise ValueError(f'prespecialization: {name} {e["at"]:#x}: bytes differ from the recipe')
                changes.append((e['at'], before, after, e['reason']))
        plan[path] = changes
    return plan


def image_paths(directory):
    """Install paths of the x86_64 cache family's images."""
    family = swift_refs.Family(directory, 'x86_64')
    try:
        return [path for _, path in family.images]
    finally:
        family.close()


def overridden(system, paths):
    """The PATHS that exist as files under the System volume SYSTEM: what dyld loads from disk instead of the cache."""
    system = Path(system)
    return sorted(p for p in paths if p not in NOT_LOADED and os.path.isfile(system/p.lstrip('/')))


def swift_sections(directory):
    """A predicate: does the x86_64 cache image at PATH carry Swift metadata (any __TEXT,__swift5_* section)?"""
    from legacy_trackpad import image_layout, plan_cache_family as plan_family

    def has_swift(path):
        found = []

        def look(read, base):
            _, sections = image_layout(read, base)
            found.extend(name for name in sections if name.startswith(b'__swift5'))
            return []
        plan_family(directory, path.encode(), look)
        return bool(found)
    return has_swift


def gate(system, directory, data=None, paths=None, swift=None):
    """Refuse (SystemExit) unless SYSTEM's overridden set equals the one the edits were made for; returns the record.

    An image the set gains or loses counts only if it carries Swift metadata: the edits depend on the overridden set
    only through the descriptors and conformances in those images (the switch edits do not depend on it), so an image
    without any __swift5 section (the Apple-silicon AGXMetal*.bundle drivers 27.x keeps on disk, which no process loads
    on this Mac) changes none of them. It is listed in the record instead."""
    data = data or load()
    found = overridden(system, image_paths(directory) if paths is None else paths)
    want = sorted(data['overridden'])
    added, gone = sorted(set(found) - set(want)), sorted(set(want) - set(found))
    if added or gone:
        swift = swift or swift_sections(directory)
        without = sorted(p for p in added + gone if not swift(p))
        added, gone = [p for p in added if p not in without], [p for p in gone if p not in without]
    else:
        without = []
    if added or gone:
        raise SystemExit('prespecialization: the image overrides other cache images than the edits were made for '
                         f'(new: {added or "none"}; gone: {gone or "none"}; each carries Swift metadata). '
                         f'Regenerate: {REGENERATE}')
    return dict(overridden=len(found), descriptor_slots_dropped=sum(data['descriptor_slots_dropped'].values()),
                blocked=data['blocked'], ignored_without_swift=without)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['plan'] and len(argv) == 2:
        plan = plan_cache_family(argv[1])
        print(json.dumps({str(p): [(o, b.hex(), a.hex(), r) for o, b, a, r in c] for p, c in plan.items()}, indent=1))
    elif argv[:1] == ['gate'] and len(argv) == 3:
        print(json.dumps(gate(argv[1], argv[2])))
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
