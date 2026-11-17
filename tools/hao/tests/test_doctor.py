"""src/doctor.py: each check against fakes; a wrong Python stops (the R11 acceptance)."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'src'))
import doctor as D        # noqa: E402

P = D.pins()


def state(results, name):
    return [r['state'] for r in results if r['name'] == name]


def runner(xcode='Xcode 27.2\nBuild version 27C5\n', metal=True):
    def run(argv, **kw):
        if argv[0].endswith('xcodebuild'):
            return subprocess.CompletedProcess(argv, 0 if xcode else 1, xcode or '', '')
        if argv[0].endswith('xcrun'):
            return subprocess.CompletedProcess(argv, 0 if metal else 1, '', '')
        raise OSError('unexpected %s' % argv)
    return run


class Python(unittest.TestCase):
    def test_wrong_python_on_a_build_mac_fails(self):
        r = D.check_python('build', P, version=(3, 12, 14), which=lambda n: '/x/' + n)
        self.assertEqual(state(r, 'python'), ['fail'])
        self.assertIn('needs 3.14', r[0]['detail'])

    def test_kit_python_is_right_on_the_usb_installer(self):
        self.assertEqual(state(D.check_python('installer', P, version=(3, 12, 14)), 'python'), ['ok'])

    def test_python314_missing_from_path(self):
        r = D.check_python('build', P, version=(3, 14, 7), which=lambda n: None)
        self.assertEqual(state(r, 'python'), ['ok', 'fail'])


class Xcode(unittest.TestCase):
    def test_needed_for_create_installer_not_for_ci(self):
        self.assertEqual(state(D.check_xcode('create-installer', P, runner(xcode='')), 'xcode'), ['fail'])
        self.assertEqual(state(D.check_xcode('ci', P, runner(xcode='')), 'xcode'), ['warn'])

    def test_version_matters_for_a_release_proof(self):
        run = runner(xcode='Xcode 26.4\n')
        self.assertEqual(state(D.check_xcode('release', P, run), 'xcode'), ['fail'])
        self.assertEqual(state(D.check_xcode('create-installer', P, run), 'xcode'), ['warn'])

    def test_no_metal_toolchain(self):
        self.assertEqual(state(D.check_xcode('create-installer', P, runner(metal=False)), 'xcode'), ['ok', 'fail'])


class Host(unittest.TestCase):
    def test_older_macos_is_reported_not_refused(self):
        self.assertEqual(state(D.check_macos(P, mac='15.6'), 'macos'), ['warn'])
        self.assertEqual(state(D.check_macos(P, mac='26.7'), 'macos'), ['ok'])

    def test_disk_against_the_release_peak(self):
        with tempfile.TemporaryDirectory() as d:
            huge = {'downloads': [{'name': 'x', 'size': 10 ** 16, 'sha256': '0' * 64, 'url': 'https://x'}]}
            self.assertEqual(state(D.check_disk(huge, d), 'disk'), ['fail'])
            saved = D.shutil.disk_usage
            D.shutil.disk_usage = lambda path: saved(path)._replace(free=10 ** 13)   # 10 TB free, whatever this Mac has
            try:
                self.assertEqual(state(D.check_disk({'downloads': []}, d), 'disk'), ['ok'])
            finally:
                D.shutil.disk_usage = saved


class Downloads(unittest.TestCase):
    REL = {'downloads': [{'name': 'a.pkg', 'url': 'https://swcdn.apple.com/a', 'mirrors': ['https://m/a']},
                         {'name': 'b.dmg', 'url': 'https://updates.cdn-apple.com/b'}]}

    def test_urls(self):
        class Resp:
            def __init__(self, status): self.status = status
            def __enter__(self): return self
            def __exit__(self, *a): return False
        ok = lambda req, timeout: Resp(200)
        gone = lambda req, timeout: Resp(404 if req.full_url.endswith('/b') else 200)
        self.assertEqual(state(D.check_urls(self.REL, P, False, ok), 'urls'), ['ok'])
        r = D.check_urls(self.REL, P, False, gone)
        self.assertEqual(state(r, 'urls'), ['fail'])
        self.assertIn('b.dmg (404)', r[0]['detail'])
        self.assertEqual(state(D.check_urls(self.REL, P, True, gone), 'urls'), ['warn'])

    def test_mirror_required_for_a_release(self):
        self.assertEqual(state(D.check_mirror(self.REL, 'create-installer'), 'mirror'), ['warn'])
        self.assertEqual(state(D.check_mirror(self.REL, 'release'), 'mirror'), ['fail'])


class Shebangs(unittest.TestCase):
    def test_counts_other_interpreters(self):
        with tempfile.TemporaryDirectory() as d:
            for name, first in (('a.py', '#!/usr/bin/env python3.14'), ('b.py', '#!/usr/bin/env python3'),
                                ('c.py', '#!/usr/bin/python3'), ('d.sh', '#!/bin/sh')):
                (Path(d) / name).write_text(first + '\n')
            files = 'a.py\nb.py\nc.py\nd.sh\n'
            run = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, files, '')
            r = D.check_shebangs(P, top=Path(d), run=run)
        self.assertEqual(r[0]['state'], 'warn')
        self.assertIn('1 name python3', r[0]['detail'])
        self.assertIn('1 name /usr/bin/python3', r[0]['detail'])


class RootPython(unittest.TestCase):
    """The launcher's rule (sudo runs only python.org's 3.14, root's alone), checked the same way by doctor."""
    def test_missing_or_user_owned_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            r = D.check_interpreter(Path(d) / 'Versions' / '3.14')
            self.assertEqual((r[0]['state'], 'missing' in r[0]['detail']), ('fail', True))
            py = Path(d) / 'Versions' / '3.14' / 'bin'
            py.mkdir(parents=True)
            (py / 'python3.14').write_text('')
            r = D.check_interpreter(Path(d) / 'Versions' / '3.14')
            self.assertEqual(r[0]['state'], 'fail')
            self.assertIn("not root's alone", r[0]['detail'])
            self.assertIn('chmod -R go-w', r[0]['fix'])


if __name__ == '__main__':
    unittest.main()
