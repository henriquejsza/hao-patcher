"""Static ObjC lookup decision lists, including conditional preattached lists.

For each selector the ordered (loaded-image predicate, IMP) branches describe
lookup for every loaded-image subset, not just the misleading all-loaded case.
Superclass edges complete the lookup graph without expanding inherited methods
quadratically. Swift runtime-completed superclass edges are recorded as OPEN.
"""
from functools import lru_cache
import hashlib
import json
import struct
from .cache import commands
from .exports import require
from .objc_transfer import CachedReader, sections
from .objc_tables import template_class_objects
from .slides import family_slides

COMMON = ('init', 'dealloc', '.cxx_destruct', 'copyWithZone:')


class MethodReader(CachedReader):
    @lru_cache(maxsize=None)
    def string(self, address):
        require(address != 0, 'null method string')
        file, offset = self.family.locate(address, 1)
        end = file.data.find(b'\0', offset, min(offset + (1 << 20), len(file.data)))
        require(end >= offset, f'unterminated method string at {address:#x}')
        return file.data[offset:end].decode('utf-8', errors='surrogateescape')

    @lru_cache(maxsize=None)
    def methods(self, address):
        flags, count = struct.unpack('<II', self.read(address, 8))
        if flags == 3 and count == 0:
            return dict(address=hex(address), flags=hex(flags), entries=[])
        try:
            result = super().methods(address)
            # objc4 searches fixed-up lists by canonical selector pointer and
            # rewinds duplicates to their first occurrence. Refuse bad sorting.
            if flags & 3 == 3:
                if flags & 0x80000000:
                    selectors = [self.selector_base + (self.number(address + 8 + i*12, '<i') & 0xffffffff)
                                 for i in range(count)]
                else:
                    selectors = [self.ptr(address + 8 + i*24) for i in range(count)]
                require(all(a <= b for a, b in zip(selectors, selectors[1:])),
                        'fixed-up method list is not selector sorted')
            return result
        except Exception as exc:
            raise ValueError(f'method list {address:#x} header={self.read(address, 8).hex()}') from exc


def decision_list(lists):
    """Canonical first-match lookup: an owner tested twice cannot win twice."""
    result = {}
    for owner, methods in lists:
        for method in methods:
            branches = result.setdefault(method['selector'], [])
            if any(branch['owner'] is None or branch['owner'] == owner for branch in branches):
                continue
            branches.append(dict(owner=owner, imp=method['imp'], types=method['types']))
    return result


def resolve(graph, key, selector, loaded):
    """Resolve one concrete static load state; refuse superclass cycles."""
    seen = set()
    while key is not None:
        require(key not in seen, 'method resolution superclass cycle')
        seen.add(key)
        node = graph[key]
        for branch in node['methods'].get(selector, ()):
            if branch['owner'] is None or branch['owner'] in loaded:
                return dict(branch, defined_by=key)
        key = node['superclass']
    return None


def inventory(family):
    reader = MethodReader(family)
    objects = {}
    for path, mh in family.images:
        for _, name, address, size in sections(commands(family, mh)):
            if name not in ('__objc_classlist', '__objc_nlclslist'):
                continue
            require(size % 8 == 0, 'unaligned class list')
            for field in range(address, address + size, 8):
                cls = reader.ptr(field)
                for obj, meta in ((cls, False), (reader.ptr(cls), True)):
                    require(obj, 'null class/metaclass')
                    if obj in objects:
                        require(objects[obj] == (path, meta), 'class identity has multiple owners')
                    objects[obj] = (path, meta)
    templates = template_class_objects(family, family_slides(family))
    # A template's method lists identify its logical image; physical segments do
    # not (Swift and ObjC objects can be co-located in other images' segments).
    extra_templates = 0
    template_details = []
    for obj, ro in templates.items():
        if obj in objects or not reader.ptr(obj + 32) & 3:
            continue
        extra_templates += 1
        # Identity must not depend on the owner words being audited. The class
        # object's address is preserved by the rebuild, so use its VA as key.
        objects[obj] = ('template@' + hex(obj), bool(reader.number(ro, '<I') & 1))
        isa = reader.ptr(obj)
        template_details.append(dict(address=hex(obj), name=reader.string(reader.ptr(ro + 24)),
                                     isa=hex(isa), metaclass_static=bool(isa)))
        if isa and isa not in objects:
            objects[isa] = ('template-metaclass@' + hex(isa), True)
    keys = {}
    for obj, (path, meta) in objects.items():
        ro = reader.ptr(obj + 32) & ~7
        name = reader.string(reader.ptr(ro + 24))
        keys[obj] = json.dumps([path, name, '+' if meta else '-'], separators=(',', ':'))
    require(len(set(keys.values())) == len(keys), 'duplicate logical class identity')
    graph = {}
    unresolved = []
    for obj, (path, meta) in objects.items():
        ro = reader.ptr(obj + 32) & ~7
        lists = []
        for entry in reader.lists(reader.ptr(ro + 32)):
            index = entry['image_index']
            require(index is None or index in reader.objc_images, 'method owner outside header array')
            lists.append((reader.objc_images[index] if index is not None else None,
                          reader.methods(entry['address'])['entries']))
        superclass = reader.ptr(obj + 8)
        if superclass and superclass not in keys:
            unresolved.append(dict(key=keys[obj], address=hex(superclass)))
        graph[keys[obj]] = dict(methods=decision_list(lists), superclass=keys.get(superclass),
                               unresolved_superclass=hex(superclass) if superclass and superclass not in keys else None)
    reader.string.cache_clear(); reader.methods.cache_clear()
    return graph, dict(objects=len(graph), template_objects=extra_templates,
                       selectors=sum(len(n['methods']) for n in graph.values()), templates=template_details,
                       unresolved_superclasses=unresolved)


def differences(before, after):
    differences = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        if old is None or new is None:
            differences.append(dict(key=key, selector=None, before=old, after=new))
            continue
        for field in ('superclass', 'unresolved_superclass'):
            if old[field] != new[field]:
                differences.append(dict(key=key, field=field, selector=None,
                                        before=old[field], after=new[field]))
        for sel in sorted(old['methods'].keys() | new['methods'].keys()):
            a, b = old['methods'].get(sel, []), new['methods'].get(sel, [])
            if a != b:
                loaded = {x['owner'] for x in a if x['owner'] is not None}
                old_resolution = resolve(before, key, sel, loaded)
                new_resolution = resolve(after, key, sel, loaded)
                dropped = old_resolution is not None and (new_resolution is None or
                          old_resolution['defined_by'] != new_resolution['defined_by'])
                differences.append(dict(key=key, selector=sel, before=a, after=b,
                                        effect='dropped' if dropped else 'changed',
                                        source_owners_loaded=sorted(loaded),
                                        source_resolution=old_resolution,
                                        candidate_resolution=new_resolution))
    return differences


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


REPORT_SOURCES = ('tools/check-method-resolution.py', 'src/dyld_rebuild/method_resolution.py',
                  'src/dyld_rebuild/objc_transfer.py', 'src/dyld_rebuild/objc_tables.py',
                  'src/dyld_rebuild/slides.py', 'src/dyld_rebuild/cache.py',
                  'src/dyld_rebuild/candidate.py',
                  'research/claude-freshcache/objc4/runtime/objc-runtime-new.h',
                  'research/claude-freshcache/objc4/runtime/objc-runtime-new.mm')


def verify_report(report, family_pins, *, policy_path=None, policy_sha256=None):
    """Certification consumes a complete, current, pinned static audit only."""
    from pathlib import Path
    from .sidecars import sha
    root = Path(__file__).resolve().parents[2]
    require((policy_path is None) == (policy_sha256 is None),
            'explicit method policy requires path and independent SHA-256')
    policy = (root/'config/method-resolution-policy.json' if policy_path is None
              else (root/Path(policy_path)).resolve())
    if policy_path is not None:
        require(policy.is_relative_to(root/'config') and policy.is_file(),
                'explicit method policy must be a repository config file')
        require(len(policy_sha256) == 64 and all(c in '0123456789abcdef' for c in policy_sha256)
                and sha(policy) == policy_sha256, 'explicit method policy hash differs')
    require(report['schema'] == 1 and report['result'] == 'PASS'
            and report['unexplained_differences'] == 0 and report['unexplained'] == []
            and report['missing_expected_differences'] == [], 'method-resolution check failed')
    require(report['policy'] == dict(path=str(policy), sha256=sha(policy)), 'method-resolution policy differs')
    require(report['source_hashes'] == {s: sha(root/s) for s in REPORT_SOURCES},
            'method-resolution checker source drift')
    def by_name(pins):
        require(len({Path(p['path']).name for p in pins}) == len(pins), 'duplicate method audit input')
        for p in pins:
            require(sha(root / Path(p['path'])) == p['sha256'], 'method audit input hash drift')
        return {Path(p['path']).name: p['sha256'] for p in pins}
    require(by_name(report['family_files']) == by_name(family_pins), 'method audit family differs')
    source_contract = json.loads((root/'config/relayout-inputs.json').read_text())
    require(by_name(report['source_files']) == by_name([p for p in source_contract['files'] if not p['path'].endswith(('.map', '.atlas'))]), 'method audit Apple source differs')
    require(report['family']['sha256'] == report['family_files'][0]['sha256']
            and report['source']['sha256'] == report['source_files'][0]['sha256'], 'method audit main pin differs')
    policy_data = json.loads(policy.read_text())
    actual = {digest([d['key'], d.get('selector'), d.get('field')]): digest(d) for d in report['all_differences']}
    require(actual == policy_data['expected_differences'], 'method audit explanation inventory differs')
    require(report['differences'] == len(actual) == report['explained_differences'], 'method audit count differs')
    return dict(result='PASS', differences=len(actual), source_inventory=report['source_inventory'],
                candidate_inventory=report['candidate_inventory'], policy=report['policy'])
