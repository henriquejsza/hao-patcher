"""Prelinked kernel collections: the key, the store, the kit's copy, and darwin27-kernel's hook installing them."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
P = runpy.run_path(str(TOP / 'pipeline' / 'prelinked_kc.py'))
HOOK = TOP / 'patches' / 'darwin27-kernel' / 'src'
FILES = P['FILES']


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.built = self.d / 'kc'; self.built.mkdir()
        for n in FILES:
            (self.built / n).write_bytes(n.encode())
        self.store = self.d / 'store'

    def share(self):
        s = self.d / 'share'
        for name in P['SOURCES']:
            f = s / 'assembly-source' / name
            f.parent.mkdir(parents=True, exist_ok=True)
            if name in ('hardware', 'tahoe-donors'):
                f.mkdir(exist_ok=True); (f / 'tool.py').write_text(name); (f / 'tests').mkdir(exist_ok=True)
                (f / 'tests' / 'test_x.py').write_text('not keyed')
            else:
                f.write_text(name)
        h = s / 'hooks' / '01-darwin27-kernel'; h.mkdir(parents=True, exist_ok=True)
        for name in P['HOOK_FILES']:
            (h / name).write_text(name)
        (h / 'inputs').mkdir(exist_ok=True); (h / 'inputs/darwin27_kernel').write_bytes(b'kernel')
        return s

    def lines(self, share):
        recipe = dict(inputs=dict(native='n', hardware='h'), oclp='fd83bda09', target='mbp92')
        return P['lines'](recipe, share, lambda item: 'row %s X' % item[4:], '01-darwin27-kernel')

    def test_key_follows_the_sources_not_their_tests(self):
        share = self.share(); lines = self.lines(share); key = P['key_of'](lines)
        self.assertIn('row darwin27_kernel X', lines); self.assertIn('row h X', lines)
        self.assertTrue(any(l.startswith('file kc-hook.sh ') for l in lines))
        (share / 'assembly-source/tahoe-donors/tests/test_x.py').write_text('changed')
        self.assertEqual(key, P['key_of'](self.lines(share)))
        (share / 'assembly-source/golden-pristine.sh').write_text('changed')
        self.assertNotEqual(key, P['key_of'](self.lines(share)))

    def test_store_then_stage_into_the_kit(self):
        share = self.share(); lines = self.lines(share); key = P['key_of'](lines)
        hook = share / 'hooks' / '01-darwin27-kernel'
        self.assertIsNone(P['stage'](self.store, key, lines, hook))          # nothing stored yet
        entry = P['store_entry'](self.store, key, lines, self.built, sha(b'kernel'), record='/r/run')
        self.assertEqual(entry['files']['SystemKernelExtensions.kc']['sha256'], sha(b'SystemKernelExtensions.kc'))
        data = P['stage'](self.store, key, lines, hook)
        self.assertEqual(data['key'], key); self.assertEqual(data['record'], '/r/run')
        self.assertEqual(data['kernel_sha256'], sha(b'kernel'))
        for n in FILES:
            self.assertEqual((hook / 'prelinked' / n).read_bytes(), n.encode())
        self.assertEqual(json.loads((hook / 'prelinked/prelinked.json').read_text())['files'], data['files'])

    def test_stage_refuses_other_lines_or_bytes(self):
        share = self.share(); lines = self.lines(share); key = P['key_of'](lines)
        P['store_entry'](self.store, key, lines, self.built, sha(b'other kernel'))
        hook = share / 'hooks' / '01-darwin27-kernel'
        with self.assertRaisesRegex(ValueError, 'linked around kernel'):
            P['stage'](self.store, key, lines, hook)
        P['store_entry'](self.store, key, lines, self.built, sha(b'kernel'))
        entry = json.loads((self.store / key / 'entry.json').read_text()); del entry['files']['SystemKernelExtensions.kc']
        (self.store / key / 'entry.json').write_text(json.dumps(entry))
        with self.assertRaisesRegex(ValueError, 'not exactly'):
            P['stage'](self.store, key, lines, hook)
        P['store_entry'](self.store, key, lines, self.built, sha(b'kernel'))
        with self.assertRaises(ValueError):
            P['stage'](self.store, key, lines + ['extra'], self.d / 'a')
        (self.store / key / 'BootKernelExtensions.kc').write_bytes(b'changed')
        b = self.d / 'b'; (b / 'inputs').mkdir(parents=True); (b / 'inputs/darwin27_kernel').write_bytes(b'kernel')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            P['stage'](self.store, key, lines, b)

    def test_store_keeps_the_newest(self):
        for i in range(P['KEEP'] + 2):
            P['store_entry'](self.store, 'k%d' % i, ['l%d' % i], self.built, 'k')
            os.utime(self.store / ('k%d' % i) / 'entry.json', (1000 + i, 1000 + i))
        P['store_entry'](self.store, 'last', ['x'], self.built, 'k')
        self.assertEqual(P['KEEP'], len(list(self.store.glob('*/entry.json'))))
        self.assertTrue((self.store / 'last').is_dir())


class HookInstallsPrelinked(unittest.TestCase):
    """darwin27-kernel's kc-hook.sh with prelinked/: checks, installs into System and Preboot, runs no kmutil."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.h = d / 'hook'; shutil.copytree(HOOK, self.h)
        (self.h / 'inputs').mkdir(); (self.h / 'inputs/darwin27_kernel').write_bytes(b'kernel')
        (self.h / 'inputs/tahoe_kmutil').write_text('#!/bin/sh\necho kmutil ran >&2; exit 9\n')
        self.sys = d / 'sys'; (self.sys / 'System/Library/Kernels').mkdir(parents=True)
        (self.sys / 'System/Library/Kernels/kernel').write_bytes(b'kernel')
        self.pre = d / 'preboot'; self.pre.mkdir()
        pl = self.h / 'prelinked'; pl.mkdir()
        files = {}
        for n in FILES:
            (pl / n).write_bytes(n.encode()); files[n] = sha(n.encode())
        self.files = files
        self.write_json(files)
        stubs = d / 'bin'; stubs.mkdir()
        (stubs / 'diskutil').write_text('#!/bin/sh\ncase "$1" in info) printf \'<?xml version="1.0"?><plist version="1.0">'
                                        '<dict><key>DeviceIdentifier</key><string>disk9s3</string><key>MountPoint</key>'
                                        '<string>%s</string></dict></plist>\' ;; esac\n' % self.pre)
        (stubs / 'install').write_text('#!/bin/sh\nargs=; while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; '
                                       '*) args="$args $1"; shift ;; esac; done\nexec /usr/bin/install $args\n')
        for s in stubs.iterdir():
            s.chmod(0o755)
        self.env = dict(os.environ, PATH='%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, OCLP_PYTHON=sys.executable,
                        PBU='PB-UUID', GRP='GROUP')

    def write_json(self, files, kernel=sha(b'kernel')):
        (self.h / 'prelinked/prelinked.json').write_text(json.dumps(dict(key='k123', files=files, kernel_sha256=kernel,
                                                                        record='/r')))

    def hook(self):
        return subprocess.run(['sh', '-eu', str(self.h / 'kc-hook.sh'), str(self.sys)], env=self.env,
                              capture_output=True, text=True)

    def test_installs_the_checked_files_without_kmutil(self):
        r = self.hook()
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertNotIn('kmutil ran', r.stderr)
        self.assertIn('installed the prelinked collections (key k123)', r.stdout)
        for n in FILES:
            self.assertEqual((self.sys / 'System/Library/KernelCollections' / n).read_bytes(), n.encode())
        for n in FILES[:2]:
            self.assertEqual((self.pre / 'GROUP/boot/System/Library/KernelCollections' / n).read_bytes(), n.encode())
        self.assertFalse((self.sys / '.darwin27-kc-build').exists())

    def test_a_changed_file_stops_the_hook(self):
        (self.h / 'prelinked/SystemKernelExtensions.kc').write_bytes(b'other')
        r = self.hook()
        self.assertNotEqual(0, r.returncode)
        self.assertIn('prelinked SystemKernelExtensions.kc is', r.stderr)
        self.assertFalse((self.sys / 'System/Library/KernelCollections').exists())

    def test_a_json_without_one_of_the_three_files_stops_the_hook(self):
        files = dict(self.files); del files['SystemKernelExtensions.kc']; self.write_json(files)
        r = self.hook()
        self.assertNotEqual(0, r.returncode); self.assertIn('not exactly', r.stderr)

    def test_collections_linked_around_another_kernel_stop_the_hook(self):
        self.write_json(self.files, kernel=sha(b'another kernel'))
        r = self.hook()
        self.assertNotEqual(0, r.returncode); self.assertIn('linked around kernel', r.stderr)

    def test_a_left_over_build_folder_is_replaced(self):
        (self.sys / '.darwin27-kc-build').mkdir(); (self.sys / '.darwin27-kc-build/old').write_text('from a failed run')
        r = self.hook()
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertFalse((self.sys / '.darwin27-kc-build').exists())


if __name__ == '__main__':
    unittest.main()
