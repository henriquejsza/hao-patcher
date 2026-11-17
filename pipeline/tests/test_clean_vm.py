"""pipeline/vm/clean-vm: base.json written and read, version match, paths, arguments, refusals, down's order.
Every VM, process and guest call goes through a fake host: no VM is made or started."""
import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import runpy

CV = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'vm' / 'clean-vm'))
TOOLS = {'sw_vers': 'ProductName:\tmacOS\nProductVersion:\t26.6\nBuildVersion:\t25G342',
         'xcodebuild': 'Xcode 26.1\nBuild version 17B55', 'clang': 'Apple clang version 17.0.0',
         'python3.14': 'Python 3.14.0', 'git': 'git version 2.50.1 (Apple Git-155)',
         'sip': 'System Integrity Protection status: disabled.', 'boot-args': 'boot-args\tamfi_get_out_of_my_way=1'}


def probe_output(tools, fail=None):
    lines = []
    for key, _ in CV['PROBES']:
        lines += ['@@begin ' + key, tools[key], '@@end %s %d' % (key, 1 if key == fail else 0)]
    return '\n'.join(lines) + '\n'


class FakeHost:
    def __init__(self, store, tools=TOOLS, mounted=True, setup_rc='0'):
        self.store, self.tools, self.mounted, self.setup_rc = Path(store), dict(tools), mounted, setup_rc
        self.calls = []
        self.registry = {}
        self.clock = 0

    def done(self, args):
        return subprocess.CompletedProcess([str(a) for a in args], 0, '', '')

    def ssdvm(self, *args):
        self.calls.append(('ssdvm',) + tuple(map(str, args)))
        Path(args[1]).mkdir(parents=True)
        return self.done(args)

    def vmctl(self, vm, *args, capture=False):
        self.calls.append(('vmctl', str(vm), args[0]))
        result = self.done(args)
        if args[:1] == ('exec',):
            script = args[1]
            if '@@begin' in script:
                result.stdout = probe_output(self.tools)
            elif 'xip --expand' in script:
                folder = Path(str(vm) + '.share') / 'clean-vm'
                (folder / 'result').write_text(self.setup_rc + '\n')
                result.stdout = 'started\n'
            elif 'mount' in script:
                result.stdout = 'MOUNTED\n' if self.mounted else ''
        return result

    def clones_py(self, *args, capture=False):
        self.calls.append(('clones',) + tuple(map(str, args)))
        result = self.done(args)
        if args[0] == 'clone':
            home = Path(args[5]) / args[1]
            result.stdout = json.dumps(dict(name=args[1], vm=str(home / 'vm'), share=str(home / 'share')))
        return result

    def start_sh(self, vm, share, mac):
        self.calls.append(('start.sh', str(vm), str(share), mac))

    def stop_sh(self, vm):
        self.calls.append(('stop.sh', str(vm)))

    def provision(self, vm, mac):
        self.calls.append(('provision', str(vm), mac))

    def new_mac(self):
        return '02:00:00:00:00:01'

    def place(self, source, target):
        self.calls.append(('place', Path(source).name, Path(target).name))
        shutil.copy2(source, target)

    def records(self, root):
        return self.registry

    def sha256(self, path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def sleep(self, seconds):
        self.clock += seconds

    def now(self):
        return self.clock


class CleanVmTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.store = self.tmp / 'store'
        (self.store / 'vm').mkdir(parents=True)
        self.inputs = {}
        for name, data in (('restore.ipsw', b'ipsw'), ('Xcode_26.1.xip', b'xip'), ('python-3.14.0-macos11.pkg', b'pkg')):
            (self.tmp / name).write_bytes(data)
            self.inputs[name] = self.tmp / name

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def make(self, host, kind='tahoe'):
        return CV['main'](['make-base', kind, str(self.inputs['restore.ipsw']),
                           '--xcode', str(self.inputs['Xcode_26.1.xip']),
                           '--python', str(self.inputs['python-3.14.0-macos11.pkg'])], host)

    def quiet(self, call, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = call(*args)
        return rc, out.getvalue(), err.getvalue()

    def test_paths(self):
        self.assertEqual(CV['base_dir']('tahoe', self.store), self.store / 'vm/base-tahoe')
        self.assertEqual(CV['base_dir']('golden', self.store), self.store / 'vm/base-golden')
        with self.assertRaises(CV['Refused']):
            CV['base_dir']('sequoia', self.store)

    def test_make_base_writes_base_json(self):
        host = FakeHost(self.store)
        rc, out, err = self.quiet(self.make, host, 'golden')
        self.assertEqual(rc, 0, err)
        base = self.store / 'vm/base-golden'
        record = json.loads((base / 'base.json').read_text())
        self.assertEqual(record['kind'], 'golden')
        self.assertEqual(record['tools'], TOOLS)
        self.assertEqual(record['inputs']['ipsw']['sha256'], hashlib.sha256(b'ipsw').hexdigest())
        self.assertEqual(record['inputs']['xcode']['sha256'], hashlib.sha256(b'xip').hexdigest())
        self.assertEqual(record['inputs']['python']['sha256'], hashlib.sha256(b'pkg').hexdigest())
        names = [c[0] for c in host.calls]
        self.assertEqual(names[:4], ['ssdvm', 'vmctl', 'provision', 'place'])
        self.assertEqual(host.calls[0], ('ssdvm', 'install', str(base), str(self.inputs['restore.ipsw'])))
        self.assertEqual(host.calls[1], ('vmctl', str(base), 'init-agent'))
        self.assertLess(names.index('start.sh'), names.index('stop.sh'))
        self.assertEqual(names[-1], 'stop.sh')
        self.assertFalse((self.store / 'vm/base-golden.share').exists())     # the setup share is removed
        # read back
        base_read, again = CV['read_base']('golden', self.store)
        self.assertEqual((base_read, again), (base, record))

    def test_make_base_refuses_an_existing_base(self):
        (self.store / 'vm/base-tahoe').mkdir()
        host = FakeHost(self.store)
        rc, out, err = self.quiet(self.make, host)
        self.assertEqual(rc, 1)
        self.assertIn('base already exists', err)
        self.assertEqual(host.calls, [])

    def test_make_base_refuses_missing_inputs(self):
        self.inputs['Xcode_26.1.xip'].unlink()
        host = FakeHost(self.store)
        rc, out, err = self.quiet(self.make, host)
        self.assertEqual(rc, 1)
        self.assertIn('--xcode is not a file', err)
        self.assertEqual(host.calls, [])

    def test_make_base_failed_setup_stops_and_writes_nothing(self):
        host = FakeHost(self.store, setup_rc='1')
        rc, out, err = self.quiet(self.make, host)
        self.assertEqual(rc, 1)
        self.assertIn('guest setup failed (exit 1)', err)
        self.assertEqual(host.calls[-1][0], 'stop.sh')
        self.assertFalse((self.store / 'vm/base-tahoe/base.json').exists())

    def test_make_base_refuses_sip_on(self):
        host = FakeHost(self.store, tools=dict(TOOLS, sip='System Integrity Protection status: enabled.'))
        rc, out, err = self.quiet(self.make, host)
        self.assertEqual(rc, 1)
        self.assertIn('SIP is not off', err)

    def test_arguments(self):
        host = FakeHost(self.store)
        for argv in (['make-base', 'tahoe', 'x.ipsw'], ['make-base', 'other', 'x.ipsw', '--xcode', 'a', '--python', 'b'],
                     ['up', 'tahoe'], ['up', 'mojave', 'n'], ['down'], []):
            with self.assertRaises(SystemExit) as x, contextlib.redirect_stderr(io.StringIO()):
                CV['main'](argv, host)
            self.assertEqual(x.exception.code, 2, argv)
        self.assertEqual(host.calls, [])

    def write_base(self, kind='tahoe', tools=TOOLS):
        base = self.store / 'vm' / ('base-' + kind)
        base.mkdir()
        (base / 'base.json').write_text(json.dumps(dict(schema=1, kind=kind, tools=tools, inputs={})))
        return base

    def test_up_without_base_refuses(self):
        host = FakeHost(self.store)
        rc, out, err = self.quiet(CV['main'], ['up', 'tahoe', 'r1'], host)
        self.assertEqual(rc, 1)
        self.assertIn('make-base tahoe', err)
        self.assertEqual(host.calls, [])

    def test_up_matching(self):
        base = self.write_base()
        host = FakeHost(self.store)
        rc, out, err = self.quiet(CV['main'], ['up', 'tahoe', 'r1'], host)
        self.assertEqual(rc, 0, err)
        vm = self.store / 'vm/r1/vm'
        self.assertEqual(host.calls[0], ('clones', 'clone', 'r1', '--base', str(base), '--root', str(self.store / 'vm')))
        self.assertEqual(host.calls[1], ('clones', 'start', str(vm), str(self.store / 'vm/r1/share')))
        self.assertNotIn('stop.sh', [c[0] for c in host.calls])
        self.assertIn('VMDIR ' + str(vm), out)
        self.assertIn('SHARE ' + str(self.store / 'vm/r1/share'), out)

    def test_up_version_mismatch_refuses_and_stops(self):
        self.write_base('golden')
        host = FakeHost(self.store, tools=dict(TOOLS, xcodebuild='Xcode 26.2\nBuild version 17C1'))
        rc, out, err = self.quiet(CV['main'], ['up', 'golden', 'r2'], host)
        self.assertEqual(rc, 1)
        self.assertIn('differs', err)
        self.assertIn('xcodebuild', err)
        self.assertEqual(host.calls[-1], ('stop.sh', str(self.store / 'vm/r2/vm')))
        self.assertNotIn('VMDIR', out)

    def test_up_share_not_mounted_refuses_and_stops(self):
        self.write_base()
        host = FakeHost(self.store, mounted=False)
        rc, out, err = self.quiet(CV['main'], ['up', 'tahoe', 'r3'], host)
        self.assertEqual(rc, 1)
        self.assertIn('share is not mounted', err)
        self.assertEqual(host.calls[-1][0], 'stop.sh')

    def test_down_stops_then_removes(self):
        host = FakeHost(self.store)
        host.registry = {'r1': dict(vm=str(self.store / 'vm/r1/vm'))}
        rc, out, err = self.quiet(CV['main'], ['down', 'r1'], host)
        self.assertEqual(rc, 0, err)
        self.assertEqual(host.calls, [('stop.sh', str(self.store / 'vm/r1/vm')),
                                      ('clones', 'remove-clone', 'r1', '--root', str(self.store / 'vm'))])

    def test_down_unknown_clone_refuses(self):
        host = FakeHost(self.store)
        rc, out, err = self.quiet(CV['main'], ['down', 'nope'], host)
        self.assertEqual(rc, 1)
        self.assertEqual(host.calls, [])

    def test_probe_parsing(self):
        self.assertEqual(CV['parse_probe'](probe_output(TOOLS)), TOOLS)
        with self.assertRaises(CV['Refused']):
            CV['parse_probe'](probe_output(TOOLS, fail='python3.14'))
        with self.assertRaises(CV['Refused']):
            CV['parse_probe']('@@begin sw_vers\nx\n@@end sw_vers 0\n')
        script = CV['probe_script']()
        for _, command in CV['PROBES']:
            self.assertIn(command, script)

    def test_recovery_extra_runs_before_the_receipt(self):
        clones = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'vm' / 'clones.py'))
        script = clones['recovery_install'](dict(identity='abc'), 'AGENT\n', CV['RECOVERY_EXTRA'])
        self.assertLess(script.index('csrutil disable'), script.index('CLONE-AGENT-INSTALLED-abc'))
        self.assertIn('amfi_get_out_of_my_way=1', script)
        self.assertNotIn('csrutil', clones['recovery_install'](dict(identity='abc'), 'AGENT\n'))

    def test_differences(self):
        self.assertEqual(CV['differences'](TOOLS, dict(TOOLS)), [])
        self.assertEqual(CV['differences'](TOOLS, dict(TOOLS, git='git version 2.51')), ['git'])


if __name__ == '__main__':
    unittest.main()
