"""Prelinked kernel collections: the Boot and System KCs a builder VM build linked, carried by a kit for an install
that cannot link them where it runs.

The stick's Recovery (Tahoe's BaseSystem) runs kmutil, but its kmutil links a kernel-only collection for the target
volume: it does not read the target's kexts. So darwin27-kernel's kc-hook installs these files instead when its
folder has prelinked/prelinked.json, after checking each file's sha256 against it.

They are valid for a kit when the System tree darwin27-kernel links around is the same as in the VM build that made
them. KEY covers what shapes that tree up to then: the input rows (Golden Gate's filesystem, the Darwin 27 kernel,
the KDK, the Tahoe donors and OCLP's hardware artifact, Tahoe's kmutil and kernel collection builder), the OCLP
revision and target, the assembly sources the base layers run (golden-pristine.sh, golden-layout.py,
kdk_intel_payload.py, fl, the donor and hardware tools) and darwin27-kernel's own hook. golden-image.py's
orchestration is not in it.

Store: store/cache/kc/KEY/ with the three files and entry.json {key, lines, files {name: {sha256, size}}, record}.
golden-run puts a VM build's collections there; golden-run --stage-kit copies them into the kit's darwin27-kernel
hook folder as prelinked/.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil

FILES = ('BootKernelExtensions.kc', 'BootKernelExtensions.kc.elides', 'SystemKernelExtensions.kc')
ROWS = ('golden_gate_userspace', 'darwin27_kernel', 'kdk', 'tahoe_kmutil', 'tahoe_kc_builder')
SOURCES = ('golden-pristine.sh', 'golden-layout.py', 'kdk_intel_payload.py', 'fl', 'hardware', 'tahoe-donors')
HOOK_FILES = ('kc-hook.sh', 'kmutil_builder.py', 'members.py')
KEEP = 3


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def tree_lines(root, name):
    """'file NAME/REL SHA' for every file under ROOT/NAME (a file or a folder), sorted; caches and tests left out."""
    base = Path(root) / name
    paths = [base] if base.is_file() else sorted(p for p in base.rglob('*') if p.is_file())
    out = []
    for p in paths:
        rel = p.relative_to(root).as_posix()
        if '__pycache__' in rel or '/tests/' in '/' + rel:
            continue
        out.append('file %s %s' % (rel, sha256(p)))
    return out


def lines(recipe, share, key_line, hook_folder):
    """The key lines of a staged kit SHARE (golden-run's share). KEY_LINE(item) is pipeline/lock.py's key_line bound to
    the store and the recipe's lock folders; HOOK_FOLDER is darwin27-kernel's folder name in SHARE/hooks."""
    share = Path(share)
    out = [key_line('row:' + row) for row in ROWS + tuple(recipe['inputs'][role] for role in sorted(recipe['inputs']))]
    out.append('oclp %s' % recipe['oclp'])
    out.append('target %s' % recipe['target'])
    for name in SOURCES:
        out += tree_lines(share / 'assembly-source', name)
    for name in HOOK_FILES:
        out += tree_lines(share / 'hooks' / hook_folder, name)
    return out


def key_of(lines):
    return hashlib.sha256(('\n'.join(lines) + '\n').encode()).hexdigest()[:24]


def store_entry(store, key, lines, folder, kernel_sha256, record=None, keep=KEEP):
    """Copy the three files from FOLDER (a VM build's work/kc) into STORE/KEY with entry.json (KERNEL_SHA256: the
    darwin27_kernel file they were linked around); keep the KEEP newest entries. Returns the entry."""
    target = Path(store) / key
    tmp = Path(store) / ('.' + key + '.new')
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    files = {}
    for name in FILES:
        shutil.copy2(Path(folder) / name, tmp / name)
        files[name] = dict(sha256=sha256(tmp / name), size=(tmp / name).stat().st_size)
    entry = dict(key=key, lines=lines, files=files, kernel_sha256=kernel_sha256, record=str(record) if record else None)
    (tmp / 'entry.json').write_text(json.dumps(entry, indent=1) + '\n')
    if target.exists():
        shutil.rmtree(target)
    os.rename(tmp, target)
    entries = sorted(Path(store).glob('*/entry.json'), key=lambda p: (p.parent.name != key, -p.stat().st_mtime))
    for old in entries[keep:]:
        shutil.rmtree(old.parent)
    return entry


def stage(store, key, lines, hook_dir):
    """Copy STORE/KEY into HOOK_DIR/prelinked (checked) with prelinked.json; None when the store has no entry for KEY.
    The entry must hold exactly FILES, linked around the kit's own kernel (HOOK_DIR/inputs/darwin27_kernel)."""
    entry_path = Path(store) / key / 'entry.json'
    if not entry_path.is_file():
        return None
    entry = json.loads(entry_path.read_text())
    if entry.get('lines') != lines:
        raise ValueError('prelinked kc %s: entry lines differ from the kit\'s (a key collision?)' % key)
    if set(entry.get('files', {})) != set(FILES):
        raise ValueError('prelinked kc %s: the entry holds %s, not exactly %s' % (key, sorted(entry.get('files', {})), FILES))
    kernel = sha256(Path(hook_dir) / 'inputs' / 'darwin27_kernel')
    if entry.get('kernel_sha256') != kernel:
        raise ValueError('prelinked kc %s: linked around kernel %s, the kit has %s' % (key, entry.get('kernel_sha256'), kernel))
    out = Path(hook_dir) / 'prelinked'
    out.mkdir(mode=0o755)
    for name, want in entry['files'].items():
        shutil.copy2(Path(store) / key / name, out / name)
        if sha256(out / name) != want['sha256']:
            raise ValueError('prelinked kc %s: %s does not match its entry' % (key, name))
    data = dict(key=key, files={n: f['sha256'] for n, f in entry['files'].items()}, kernel_sha256=kernel,
                record=entry.get('record'))
    (out / 'prelinked.json').write_text(json.dumps(data, indent=1, sort_keys=True) + '\n')
    return data
