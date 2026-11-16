"""src/progress.py: a backend's output goes to the log; the screen gets the install's phases in plain words."""
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'src'))
import console as CON      # noqa: E402
import progress as PROG    # noqa: E402

ASSEMBLY = '''golden-assemble.sh: caffeinate -dimsu keeps this Mac awake until the assembly ends (pid 1241)
tar: Could not pack extended attributes: Too many levels of symbolic links
STEP layout
Started partitioning on disk0
STEP golden-system
STEP golden-system
RESULT rc=0
STEP group-volumes
STEP golden-finalize
STEP golden-data
STEP tahoe-extensions
STEP boot-and-esp
STEP hardware
{"installed": ["AppleIntelHD4000Graphics.kext"]}
STEP recipes
STEP recipe darwin27-kernel
STEP recipe golden-gate-userspace
@hao {"ev": "progress", "done": 3, "total": 4, "unit": "files"}
STEP recipe golden-gate-hello
STEP recipe golden-gate-store
STEP snapshot
STEP posts
STEP post hao-opencore
STEP post golden-gate-shader-caches
STEP efi-bundle
Volume EFI on disk0s1 unmounted
RESULT rc=0
'''
GROUPS = {'base': ['darwin27-kernel', 'golden-gate-userspace', 'hao-opencore'],
          'metal-3802': ['golden-gate-hello'], 'intel-hd4000': ['golden-gate-shader-caches'],
          '(no pack)': ['golden-gate-store']}


class Pipe(io.StringIO):
    encoding = 'utf-8'

    def isatty(self):
        return False


class Tty(Pipe):
    def isatty(self):
        return True


class FakeProcess:
    def __init__(self, text, rc):
        self.stdout = io.BytesIO(text.encode())
        self.rc = rc

    def wait(self):
        return self.rc

    def terminate(self):
        pass


def popen_of(text, rc=0, seen=None):
    def popen(argv, **kw):
        if seen is not None:
            seen.append((argv, kw))
        return FakeProcess(text, rc)
    return popen


def render(text=ASSEMBLY, rc=0, level='steps', out=None, env=None):
    out = out if out is not None else Pipe()
    c = CON.Console(level, out=out, err=out, env=env if env is not None else {'TERM': 'xterm-256color'})
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / 'install.log'
        r = PROG.Runner(c, 'install', groups=GROUPS, log=log, popen=popen_of(text, rc), env={})
        got = r(['sh', '/Volumes/HAO/kit/assembly-source/golden-assemble.sh', 'KIT', 'LOCAL'])
        logged = log.read_text()
    return got, out.getvalue(), logged, r, c


class Steps(unittest.TestCase):
    def test_phases_in_plain_words(self):
        rc, out, logged, _, _ = render()
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        heads = [l for l in lines if l.startswith('[')]
        self.assertEqual(heads[0], '[1/7] Lay out the disk')
        self.assertEqual([h.split('  ')[0] for h in heads],
                         ['[1/7] Lay out the disk', '[2/7] Copy macOS 27', '[3/7] Add Intel support',
                          '[4/7] Link the kernel', '[5/7] Apply packs', '[6/7] Seal', '[7/7] Make it bootable'])
        self.assertIn('  copy the installer\'s tools and Python  ✓', lines)
        self.assertIn('  kernel collections linked, kernel repairs bound  ✓', lines)
        self.assertIn('  base                   1 recipe  ✓', lines)          # userspace (the kernel is [4/7])
        self.assertIn('  metal-3802             1 recipe  ✓', lines)
        self.assertIn('  other fixes            1 recipe  ✓', lines)
        self.assertIn('  settings, caches and the OpenCore configuration  2 recipes  ✓', lines)
        self.assertEqual(sum('the System volume' in l for l in lines), 1)          # golden-pristine's repeat
        self.assertTrue(lines[-1].startswith('  unmount the new volumes  ✓'))

    def test_internal_names_and_chatter_only_in_the_log(self):
        _, out, logged, _, _ = render()
        for word in ('golden-gate-userspace', 'caffeinate', 'tar:', 'RESULT', 'Volume EFI', 'installed', 'recipe darwin'):
            self.assertNotIn(word, out)
            self.assertIn(word, logged)
        self.assertIn('### exit 0', logged)

    def test_failure_names_the_last_error_and_the_log(self):
        text = ASSEMBLY.split('STEP snapshot')[0] + 'STEP snapshot\nunmount of /Volumes/macOS refused: Resource busy\nRESULT rc=1\n'
        rc, out, _, r, c = render(text, rc=1)
        self.assertEqual(rc, 1)
        self.assertIn('  update Preboot, bless, take the system snapshot  ✗', out)
        x = r.explain(CON.Stopped('the build onto /dev/disk0 failed (exit 1) in step snapshot',
                                  why='the disk is erased and incomplete; it will not start', options=['run it again']))
        self.assertIn('Resource busy', x.cause)
        self.assertTrue(x.log.endswith('install.log'))
        err = Pipe()
        c2 = CON.Console('steps', out=err, err=err, env={})
        c2.stopped(x)
        report = err.getvalue()
        for part in ('STOPPED', 'What happened', 'Why it matters', 'Likely cause', 'What you can do', '1  run it again',
                     'Log: '):
            self.assertIn(part, report)

    def test_a_backend_stop_event_replaces_the_generic_report(self):
        text = 'STEP layout\n@hao {"ev": "stop", "what": "the disk is too small", "options": ["use a 256 GB disk"]}\n'
        _, _, _, r, _ = render(text, rc=2)
        x = r.explain(CON.Stopped('the build failed (exit 2)', options=['run it again']))
        self.assertEqual(x.what, 'the disk is too small')
        self.assertEqual(x.options, ['use a 256 GB disk', 'run it again'])

    def test_quiet_is_one_bar(self):
        _, out, _, _, _ = render(level='quiet')
        self.assertNotIn('[1/7]', out)
        self.assertNotIn('Apply packs', out)
        self.assertEqual(out.strip().splitlines()[-1].split()[:3], ['Installing', 'macOS', '27'])
        self.assertIn('100%', out)

    def test_json_level_prints_events_only(self):
        _, out, _, _, c = render(level='json')
        import json
        evs = [json.loads(l) for l in out.splitlines()]
        self.assertIn('step.start', {e['ev'] for e in evs})
        self.assertIn('backend', {e['ev'] for e in evs})
        self.assertFalse(any('\033[' in l for l in out.splitlines()))

    def test_terminal_redraws_in_place_with_colour(self):
        _, out, _, _, _ = render(out=Tty())
        self.assertIn('\r\033[K', out)
        self.assertIn('\033[1m[1/7] Lay out the disk\033[0m', out)
        self.assertIn('\033[38;5;28m✓\033[0m', out)

    def test_no_colour_and_dumb_terminal_are_plain(self):
        for env in ({'NO_COLOR': '1', 'TERM': 'xterm'}, {'TERM': 'dumb'}):
            _, out, _, _, _ = render(out=Tty(), env=env)
            self.assertNotIn('\033[', out)
            self.assertNotIn('\r', out)

    def test_the_child_knows_it_is_rendered(self):
        seen = []
        c = CON.Console('steps', out=Pipe(), env={})
        with tempfile.TemporaryDirectory() as d:
            PROG.Runner(c, 'x', log=Path(d) / 'x.log', popen=popen_of('', 0, seen), env={'A': 'b'})(['true'])
        self.assertEqual(seen[0][1]['env']['HAO_EVENTS'], '1')
        self.assertEqual(seen[0][1]['env']['A'], 'b')

    def test_stage_kit_is_one_line(self):
        text = '+ zsh /x/pipeline/stages/inputs.sh a b\nINFO:root:- Adding Lilu.kext 1.7.2\n\033[3J\033[H\033[2J\nKit staged: /k\n'
        out = Pipe()
        c = CON.Console('steps', out=out, env={})
        with tempfile.TemporaryDirectory() as d:
            rc = PROG.Runner(c, 'create-installer', log=Path(d) / 'c.log', popen=popen_of(text), env={})(
                ['python3', '-I', 'golden-run', 'a.json', '--stage-kit'])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue().splitlines(),
                         ['  prepare the kit: each changed file made once, checked and signed  ✓'])


class Live(unittest.TestCase):
    def test_heartbeat_without_a_terminal(self):
        now = [0.0]
        out = Pipe()
        c = CON.Console('steps', out=out, env={}, clock=lambda: now[0])
        t = c.task('  build the system cryptex')
        now[0] = 31
        t.update()
        now[0] = 45
        t.update()
        now[0] = 62
        t.update()
        t.end(True)
        self.assertEqual(out.getvalue().splitlines(), [
            '  ... build the system cryptex (31s so far)',
            '  ... build the system cryptex (1m 02s so far)',
            '  build the system cryptex  ✓  1m 02s'])

    def test_ascii_when_not_utf8_or_asked(self):
        c = CON.Console('steps', out=Pipe(), env={'HAO_ASCII': '1'})
        self.assertFalse(c.utf)
        self.assertEqual(CON.bar(0.5, 4, utf=False), '##..')
        self.assertEqual(plain_task(c, 2, 4), '  x ##########.......... 2/4 files')

    def test_fit_keeps_a_redrawn_line_on_one_row(self):
        s = '\033[1mabcdefghij\033[0m'
        self.assertEqual(CON.plain(CON.fit(s, 5)), 'abcd…')
        self.assertEqual(CON.fit('abc', 5), 'abc')

    def test_elapsed(self):
        self.assertEqual([CON.elapsed(s) for s in (5, 232, 3725)], ['5s', '3m 52s', '1h 02m'])


def plain_task(c, done, total):
    t = c.task('  x', total=total, unit='files')
    t.update(done=done)
    line = CON.plain(t.render(final=True))
    t.drop()
    return line


class Hooks(unittest.TestCase):
    def test_entry_point_routes_backends_through_the_console(self):
        import importlib.machinery
        import importlib.util
        import types
        loader = importlib.machinery.SourceFileLoader('hao_entry', str(HERE.parent / 'hao'))
        spec = importlib.util.spec_from_loader('hao_entry', loader)
        hao = importlib.util.module_from_spec(spec)
        loader.exec_module(hao)
        calls = []
        build = types.SimpleNamespace(
            resolve=lambda a, c, cmd: ('profile', 'path', 'asm', {'base': ['x']}),
            show_steps=lambda c, cmd, groups: calls.append(('plan', cmd)),
            STEPS={'install': ('a', 'b')})
        inst = types.SimpleNamespace(prepare_kit=lambda a, c, path, run=None: calls.append(('kit', run)))
        c = CON.Console('steps', out=Pipe(), env={})
        c.run = PROG.Runner(c, 'install', log='/dev/null')
        a = types.SimpleNamespace(dry_run=False)
        hao.hook_backends(a, c, build, inst)
        build.resolve(a, c, 'install')
        self.assertEqual(c.run.groups, {'base': ['x']})
        build.show_steps(c, 'install', {})                  # default level, a real install: no plan before ERASE
        build.show_steps(c, 'create-installer', {})
        inst.prepare_kit(a, c, 'p')
        self.assertEqual(calls, [('plan', 'create-installer'), ('kit', c.run)])
        hao.hook_backends(a, c, build, inst)                  # twice wraps once
        self.assertEqual(build.resolve.original.__name__, '<lambda>')


if __name__ == '__main__':
    unittest.main()
