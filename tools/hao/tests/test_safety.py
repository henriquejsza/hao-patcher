"""The security review's fixes (src/safety.py and its callers): no symlink is written through or read as root, a
report never takes over an existing file, sudo drops hao's developer variables, external text reaches the terminal
as text, verify stays inside its root."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'src'))
import safety as SAFE      # noqa: E402
import report as REP       # noqa: E402
import verify as VERIFY    # noqa: E402


class Files(unittest.TestCase):
    def test_create_refuses_a_planted_symlink_and_an_existing_file(self):
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / 'victim'
            victim.write_text('keep')
            (Path(d) / 'out').symlink_to(victim)
            with self.assertRaises(OSError):
                SAFE.create(Path(d) / 'out', 'x')
            with self.assertRaises(FileExistsError):
                SAFE.create(victim, 'x')
            self.assertEqual(victim.read_text(), 'keep')
            p = SAFE.create(Path(d) / 'new', 'x')
            self.assertEqual(oct(p.stat().st_mode & 0o777), '0o600')

    def test_report_write_takes_a_new_name_and_leaves_the_symlink_target_alone(self):
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / 'victim'
            victim.write_text('keep')
            (Path(d) / 'hao-report.txt').symlink_to(victim)
            out = REP.write(Path(d) / 'hao-report.txt', 'report', env={})
            self.assertEqual(out.name, 'hao-report-1.txt')
            self.assertEqual(victim.read_text(), 'keep')
            self.assertEqual(out.read_text(), 'report')

    def test_read_small_refuses_symlinks_fifos_big_files_and_other_owners(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'a.json'
            f.write_text('{}')
            (Path(d) / 'link.json').symlink_to(f)
            os.mkfifo(str(Path(d) / 'fifo.json'))
            self.assertEqual(SAFE.read_small(f), '{}')
            self.assertIsNone(SAFE.read_small(Path(d) / 'link.json'))
            self.assertIsNone(SAFE.read_small(Path(d) / 'fifo.json'))
            self.assertIsNone(SAFE.read_small(f, limit=1))
            self.assertIsNone(SAFE.read_small(f, owners={os.getuid() + 12345}) if os.getuid() else None)

    def test_last_log_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            secret = Path(d) / 'secret.json'
            secret.write_text('{"token": "x"}')
            (Path(d) / 'install-20991231-235959.json').symlink_to(secret)
            real = Path(d) / 'install-20261117-000000.json'
            real.write_text('{"command": "install", "events": []}')
            self.assertEqual(REP.last_log([d], env={}), real)
            self.assertIn('not read', REP._json(Path(d) / 'install-20991231-235959.json', env={}))

    def test_logs_are_private(self):
        with tempfile.TemporaryDirectory() as d:
            p = REP.save_log('aot', ['aot'], [], folder=Path(d) / 'logs', ver={})
            self.assertEqual(oct(p.stat().st_mode & 0o777), '0o600')
            self.assertEqual(oct((Path(d) / 'logs').stat().st_mode & 0o777), '0o700')


class Environment(unittest.TestCase):
    def test_sudo_drops_developer_variables(self):
        env = {'HAO_LAUNCHER': '/tmp/x', 'HAO_LOGS': '/tmp/l', 'HAO_STICK': '/tmp/s', 'TMPDIR': '/tmp/t',
               'PATH': '/opt/evil/bin:/usr/bin', 'HAO_THEME': 'dark', 'SUDO_USER': 'u', 'SUDO_UID': '501'}
        gone = SAFE.harden_env(env, euid=0)
        self.assertEqual(sorted(gone), ['HAO_LAUNCHER', 'HAO_LOGS', 'HAO_STICK', 'TMPDIR'])
        self.assertEqual(env['PATH'], SAFE.SYSTEM_PATH)
        self.assertEqual(env['HAO_THEME'], 'dark')

    def test_recovery_root_and_users_keep_them(self):
        env = {'HAO_STICK': '/Volumes/HAO', 'PATH': '/x'}
        self.assertEqual(SAFE.harden_env(env, euid=0), [])
        self.assertEqual(env['HAO_STICK'], '/Volumes/HAO')
        env = {'HAO_LAUNCHER': '/tmp/x', 'SUDO_USER': 'u'}
        self.assertEqual(SAFE.harden_env(env, euid=501), [])


class Text(unittest.TestCase):
    def test_control_sequences_are_shown_as_text(self):
        self.assertEqual(SAFE.text('ok\x1b[2J\x1b]8;;http://x\x07link'), 'ok\\x1b[2J\\x1b]8;;http://x\\x07link')
        self.assertEqual(SAFE.text('abc‮def'), 'abc\\u202edef')
        self.assertEqual(SAFE.text('a\tb'), 'a\tb')

    def test_backend_lines_and_stops_are_sanitized(self):
        import console as CON
        import progress as PROG
        sys.path.insert(0, str(HERE))
        from test_progress import popen_of, Pipe
        text = ('STEP layout\nerror: \x1b[2Jbad\n@hao {"ev": "stop", "what": "x\\u001b[31my", "options": ["a\\u001b]8;;z"]}\n')
        out = Pipe()
        c = CON.Console('steps', out=out, err=out, env={})
        with tempfile.TemporaryDirectory() as d:
            r = PROG.Runner(c, 'install', log=Path(d) / 'l.log', popen=popen_of(text, 1), env={})
            r(['sh', 'golden-assemble.sh', 'K', 'L'])
        self.assertNotIn('\x1b', r.error)
        x = r.explain(CON.Stopped('failed'))
        self.assertEqual(x.what, 'x\\x1b[31my')
        self.assertEqual(x.options[0], 'a\\x1b]8;;z')


class Verify(unittest.TestCase):
    def test_manifest_paths_stay_inside_the_root(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'root'
            (root / 'usr').mkdir(parents=True)
            (Path(d) / 'outside').mkdir()
            (root / 'link').symlink_to(Path(d) / 'outside')
            for bad in ('/etc/passwd', '../outside/x', 'usr/../../outside/x', './usr/x', 'usr//x', 'link/x'):
                self.assertIsNone(VERIFY.inside(root, None, bad), bad)
            self.assertEqual(VERIFY.inside(root, None, 'usr/x'), root / 'usr' / 'x')


if __name__ == '__main__':
    unittest.main()
