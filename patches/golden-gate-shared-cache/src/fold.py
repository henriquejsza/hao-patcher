"""fold.py: install a rebuilt x86_64 shared cache family that holds the image's on-disk providers (golden-gate-shared-cache).

The rebuilt family (the shared-cache generator's artifact, row rebuilt_cache) was made from an image's installed x86_64
cache, so it already carries golden-gate-userspace's in-cache repairs, plus the System files listed in its
retired-roots.txt as cache images. This recipe:
1. checks the artifact's roots against src/providers.txt (every R line, only R and C lines);
2. checks every root's bytes on this System against the artifact's provider-provenance.json: the cache must hold the
   bytes this image would otherwise load from disk;
3. checks that the artifact was made from this image's cache: its recorded input files equal the x86_64 files of the
   OS cryptex golden-gate-userspace built, either as built or with that recipe's Swift prespecialization edits taken
   back out (the edits a cache without overridden images does not need);
4. builds a new sealed OS cryptex: the current one's files with the x86_64 family replaced by the artifact's,
   4 KiB code pages, every Swift metadata reference checked;
5. removes the roots from System and stops unless no image of the new family is left on disk (dyld itself aside).

    python3.14 -I fold.py install SYSTEM ARTIFACT        in the builder VM (env GRP, PBU), from src/kc-hook.sh
    python3.14 -I fold.py check SYSTEM ARTIFACT          steps 1-2 only, read-only
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
# staged: build/userspace (make.sh); in the checkout: golden-gate-userspace's own src
USERSPACE = HERE/'build/userspace' if (HERE/'build/userspace').is_dir() else HERE.parents[1]/'golden-gate-userspace/src'
sys.path.insert(0, str(USERSPACE))
import prespecialization  # noqa: E402
import swift_refs  # noqa: E402

PROVIDERS = HERE/'providers.txt'
PREFIX = 'dyld_shared_cache_x86_64'
DYLD = 'System/Library/dyld'
RECORD = 'System/Library/CoreServices/golden-gate-shared-cache.json'


class Refused(SystemExit):
    def __init__(self, message):
        super().__init__('golden-gate-shared-cache: ' + message)


def sha256(path, chunk=1 << 24):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        while block := stream.read(chunk):
            h.update(block)
    return h.hexdigest()


def reviewed(path=PROVIDERS):
    """(required, companions): install paths without the leading slash."""
    required, companions = set(), set()
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        kind, rel = line.split(None, 1)
        {'R': required, 'C': companions}[kind].add(rel.strip().lstrip('/'))
    return required, companions


def cache_files(directory):
    """The x86_64 cache family's files in DIRECTORY (main, subcaches, .map, .atlas), by name."""
    return sorted(p.name for p in Path(directory).iterdir() if p.name.startswith(PREFIX) and not p.is_symlink())


def load_artifact(artifact):
    """What this recipe reads from the generator's artifact: its cache files, retired roots, the provider bytes and the
    input cache it was made from."""
    artifact = Path(artifact)
    build = json.loads((artifact/'build.json').read_text())
    system = str(build['system']).rstrip('/') + '/'
    roots = [line.strip().lstrip('/') for line in (artifact/'retired-roots.txt').read_text().splitlines()
             if line.strip() and not line.startswith('#')]
    providers = {}
    for entry in json.loads((artifact/'provider-provenance.json').read_text()):
        path = str(entry['path'])
        if not path.startswith(system):
            raise Refused(f'provider {entry.get("provider")}: {path} is not under the artifact system {system}')
        providers[path[len(system):]] = entry['sha256']
    inputs = {}
    for entry in build.get('inputs', []):
        path = Path(entry['path'])
        if path.name.startswith(PREFIX) and path.parent.as_posix().endswith('/' + DYLD) \
                and '/DriverKit/' not in path.as_posix():
            if inputs.setdefault(path.name, entry['sha256']) != entry['sha256']:
                raise Refused(f'build.json names two input caches for {path.name}')
    files = cache_files(artifact)
    if PREFIX not in files:
        raise Refused(f'{artifact} has no {PREFIX}')
    if not inputs or PREFIX not in inputs:
        raise Refused('build.json does not record the input cache family (inputs: .../System/Library/dyld/'
                      f'{PREFIX}* with sha256)')
    return dict(files=files, roots=roots, providers=providers, inputs=inputs, revision=build.get('revision'),
                git_commit=build.get('git_commit'), git_dirty=build.get('git_dirty'))


def check_roots(roots, required, companions):
    """The artifact's roots are the reviewed providers: all required ones, nothing unreviewed, no duplicates."""
    found = set(roots)
    if len(found) != len(roots):
        raise Refused('retired-roots.txt lists a root twice')
    unreviewed, missing = sorted(found - required - companions), sorted(required - found)
    if unreviewed or missing:
        raise Refused(f'retired roots differ from src/providers.txt (not reviewed: {unreviewed or "none"}; '
                      f'required but not folded in: {missing or "none"})')


def check_providers(system, roots, providers):
    """Every root is on SYSTEM with the bytes the artifact folded in; returns {root: sha256}."""
    system, problems, found = Path(system), [], {}
    for root in roots:
        want = providers.get(root)
        path = system/root
        if want is None:
            problems.append(f'{root}: no provider-provenance record')
        elif path.is_symlink() or not path.is_file():
            problems.append(f'{root}: not a file on this System')
        elif (have := sha256(path)) != want:
            problems.append(f'{root}: {have[:12]} on this System, the cache holds {want[:12]}')
        else:
            found[root] = want
    if problems:
        raise Refused(f'{len(problems)} provider(s) differ from the artifact (rebuild it from this image): '
                      + '; '.join(problems))
    return found


def unedited(path, edits, workspace, resign):
    """sha256 of PATH with the prespecialization EDITS [(offset, before, after, reason)] taken back out and the file
    re-signed (RESIGN(path, force=True)), from a copy in WORKSPACE; None if PATH does not carry the edits."""
    copy = Path(workspace)/('.unedited-' + Path(path).name)
    shutil.copyfile(path, copy)
    try:
        with copy.open('r+b') as stream:
            for offset, before, after, _ in edits:
                stream.seek(offset)
                if stream.read(len(after)) != after:
                    return None
                stream.seek(offset)
                stream.write(before)
        resign(copy, force=True)
        return sha256(copy)
    finally:
        copy.unlink()


def prespecialization_edits(directory):
    """{file name: [(offset, before, after, reason)]} of golden-gate-userspace's prespecialization data, by the data's
    sites (the UUID is the pristine cache's, which the installed one keeps)."""
    data = prespecialization.load()
    return {name: [(e['at'], bytes.fromhex(e['before']), bytes.fromhex(e['after']), e['reason'])
                   for e in entry['edits']]
            for name, entry in data['files'].items() if (Path(directory)/name).is_file()}


def match_input(directory, inputs, workspace, resign, edits=None):
    """How the cache family in DIRECTORY relates to the artifact's INPUTS {name: sha256}: 'as-built' or
    'without-prespecialization'; refuses otherwise."""
    directory = Path(directory)
    current = cache_files(directory)
    if sorted(inputs) != current:
        raise Refused(f'the artifact was made from cache files {sorted(inputs)}, this image has {current}')
    have = {name: sha256(directory/name) for name in current}
    differ = sorted(n for n in current if have[n] != inputs[n])
    if not differ:
        return 'as-built'
    edits = prespecialization_edits(directory) if edits is None else edits
    if set(differ) <= set(edits) and all(unedited(directory/n, edits[n], workspace, resign) == inputs[n]
                                          for n in differ):
        return 'without-prespecialization'
    raise Refused(f'the artifact was made from another cache (differs: {differ}); rebuild it from this image\'s '
                  'OS cryptex')


def replace_cache(dyld, artifact, files):
    """Replace the x86_64 family in DYLD by the artifact's FILES, each written to a new file and given the owner, mode
    and flags of the old main cache file; returns the names removed and installed."""
    dyld, artifact = Path(dyld), Path(artifact)
    reference = (dyld/PREFIX).stat()
    removed = cache_files(dyld)
    for name in removed:
        path = dyld/name
        os.chflags(path, 0)
        path.unlink()
    for name in files:
        temporary = dyld/('.new-' + name)
        shutil.copyfile(artifact/name, temporary)
        os.chown(temporary, reference.st_uid, reference.st_gid)
        os.chmod(temporary, reference.st_mode & 0o7777)
        os.replace(temporary, dyld/name)
        os.chflags(dyld/name, reference.st_flags)
    return removed, list(files)


def retire(system, roots):
    """Remove the ROOTS from SYSTEM (the cache now holds them)."""
    for root in roots:
        path = Path(system)/root
        os.chflags(path, 0)
        path.unlink()
        print(f'golden-gate-shared-cache: removed /{root}', flush=True)


def gate(system, image_paths):
    """Refuse unless no image of the cache family (IMAGE_PATHS, install paths) is a file on SYSTEM, dyld aside."""
    left = prespecialization.overridden(system, image_paths)
    if left:
        raise Refused(f'{len(left)} cache image(s) still on disk, dyld would load them: {left}')
    return 0


def install(system, artifact):   # pragma: no cover - builder VM only (APFS images, Preboot)
    from cryptex import CRYPTEX_KEEP, image_mount, logical_size, new_image, remove, replace_tree, run, seal_image
    from cache_pages import resign_file
    from install import volume_mount
    system, artifact = Path(system), Path(artifact)
    started = time.monotonic()
    art = load_artifact(artifact)
    required, companions = reviewed()
    check_roots(art['roots'], required, companions)
    providers = check_providers(system, art['roots'], art['providers'])
    group, preboot_device = os.environ['GRP'], os.environ['PBU']
    workspace = Path(tempfile.mkdtemp(prefix='golden-gate-shared-cache-'))
    record = dict(artifact=artifact.resolve().name, generator_revision=art['revision'],
                  generator_commit=art['git_commit'], generator_dirty=art['git_dirty'], providers=providers)
    with ExitStack() as stack:
        preboot = stack.enter_context(volume_mount(preboot_device, workspace/'preboot'))
        current = preboot/group/'cryptex1/current'
        work = current/'.golden-gate-shared-cache-os.dmg'
        remove(work)
        with image_mount(current/'os.dmg', workspace/'built-os') as built:
            record['input'] = match_input(built/DYLD, art['inputs'], workspace, resign_file)
            size = logical_size(built) + sum((artifact/n).stat().st_size for n in art['files']) + (2 << 30)
            new_image(work, size, built)
            metadata = built.stat()
            with image_mount(work, workspace/'folded-os', writable=True) as mount:
                replace_tree(built, mount, CRYPTEX_KEEP)
                record['removed'], record['installed'] = replace_cache(mount/DYLD, artifact, art['files'])
                record['resigned_4k'] = [n for n in art['files'] if not n.endswith(('.map', '.atlas'))
                                         and resign_file(mount/DYLD/n)]
                images, totals, issues = swift_refs.verify(mount/DYLD, 'x86_64')
                if issues:
                    raise Refused(f'{len(issues)} bad Swift metadata references, first: {issues[0]}')
                record['swift_references_x86_64'] = dict(images=images, **totals, bad=0)
                image_paths = prespecialization.image_paths(mount/DYLD)
                record['images'] = len(image_paths)
                os.chmod(mount, metadata.st_mode & 0o7777)
                os.chflags(mount, metadata.st_flags)
        record['seal'] = seal_image(work)
        remove(current/'os.clone.dmg')
        remove(current/'os.dmg')
        os.replace(work, current/'os.dmg')
        run('cp', '-c', current/'os.dmg', current/'os.clone.dmg')
    retire(system, art['roots'])
    record['overridden'] = gate(system, image_paths)
    record['seconds'] = round(time.monotonic() - started, 1)
    out = system/RECORD
    out.write_text(json.dumps(record, indent=2) + '\n')
    os.chmod(out, 0o644)
    print('golden-gate-shared-cache:', json.dumps({k: v for k, v in record.items() if k != 'providers'}), flush=True)
    shutil.rmtree(workspace)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 3 and argv[0] == 'install':
        install(argv[1], argv[2])
    elif len(argv) == 3 and argv[0] == 'check':
        art = load_artifact(argv[2])
        check_roots(art['roots'], *reviewed())
        print(json.dumps(check_providers(argv[1], art['roots'], art['providers']), indent=1))
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
