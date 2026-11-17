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

    def test_folder_read_refuses_symlinks_fifos_big_files_and_other_owners(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'a.json'
            f.write_text('{}')
            (Path(d) / 'link.json').symlink_to(f)
            os.mkfifo(str(Path(d) / 'fifo.json'))
            with SAFE.Folder(d, {os.geteuid()}, private=False) as pinned:
                self.assertEqual(pinned.read('a.json'), '{}')
                self.assertIsNone(pinned.read('link.json'))
                self.assertIsNone(pinned.read('fifo.json'))
                self.assertIsNone(pinned.read('a.json', limit=1))
            with SAFE.Folder(d, {os.geteuid()}, private=False) as pinned:
                pinned.owners = {os.geteuid() + 12345}          # only that owner's files are read
                self.assertIsNone(pinned.read('a.json'))

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


class Folders(unittest.TestCase):
    def test_folder_refuses_links_at_and_above_it_and_narrows_its_mode(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / 'real'
            (real / 'logs').mkdir(parents=True)
            (Path(d) / 'link').symlink_to(real)
            (Path(d) / 'logs-link').symlink_to(real / 'logs')
            for bad in (Path(d) / 'link' / 'logs', Path(d) / 'logs-link'):
                with self.assertRaises(OSError, msg=bad):
                    SAFE.own_folder(bad)
            (real / 'logs').chmod(0o777)
            SAFE.own_folder(real / 'logs').close()
            self.assertEqual(oct((real / 'logs').stat().st_mode & 0o777), '0o700')
            with self.assertRaises(OSError):                     # another user's folder
                SAFE.Folder(real / 'logs', {os.geteuid() + 12345})

    def test_a_folder_swapped_after_it_was_pinned_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            logs, elsewhere = Path(d) / 'logs', Path(d) / 'elsewhere'
            elsewhere.mkdir()
            with SAFE.own_folder(logs) as pinned:
                logs.rename(Path(d) / 'moved')
                logs.symlink_to(elsewhere)                       # the name now leads elsewhere
                pinned.create('x.json', '{}')
                with pinned.open_log('a.log') as f:
                    f.write('line')
            self.assertEqual(list(elsewhere.iterdir()), [])
            self.assertEqual(sorted(x.name for x in (Path(d) / 'moved').iterdir()), ['a.log', 'x.json'])

    def test_open_log_refuses_a_fifo_and_a_hard_link(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(str(Path(d) / 'fifo.log'))
            with self.assertRaises(OSError):
                SAFE.open_log(Path(d) / 'fifo.log')
            (Path(d) / 'other').write_text('keep')
            os.link(str(Path(d) / 'other'), str(Path(d) / 'hard.log'))
            with self.assertRaises(OSError):
                SAFE.open_log(Path(d) / 'hard.log')
            self.assertEqual((Path(d) / 'other').read_text(), 'keep')
            (Path(d) / 'old.log').write_text('x')
            (Path(d) / 'old.log').chmod(0o644)
            SAFE.open_log(Path(d) / 'old.log').close()
            self.assertEqual(oct((Path(d) / 'old.log').stat().st_mode & 0o777), '0o600')

    def test_logs_in_a_symlinked_folder_are_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / 'protected'
            real.mkdir()
            (real / 'install-20991231-000000.json').write_text('{"secret": 1}')
            (Path(d) / 'logs').symlink_to(real)
            self.assertIsNone(REP.last_log([Path(d) / 'logs'], env={}))
            self.assertIsNotNone(REP.last_log([real], env={}))


class AsUser(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, 'needs root (sudo)')
    def test_root_writes_a_report_as_the_sudo_user(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o700)                  # root's folder: the user may not write here
            with self.assertRaises(OSError):
                SAFE.as_user((65534, 65534), lambda: str(SAFE.create(Path(d) / 'r.txt', 'x')))
            self.assertFalse((Path(d) / 'r.txt').exists())

    def test_errors_come_back(self):
        if os.geteuid() == 0:
            self.skipTest('as root the child could change user')
        with self.assertRaises(OSError):         # setuid to another user fails for a normal user, in the child
            SAFE.as_user((0, 0), lambda: 'never')


class Redaction(unittest.TestCase):
    def test_secrets_in_fields_words_and_urls(self):
        text = REP.scrub('{"password": "hunter2", "api_key": "k1"} token=abc Authorization: Bearer xyz '
                         'https://h/p?q=1#zz9frag', {})
        for secret in ('hunter2', 'k1', 'abc', 'xyz', 'q=1', 'zz9frag'):
            self.assertNotIn(secret, text)


class Environment(unittest.TestCase):
    def test_sudo_drops_developer_variables(self):
        env = {'HAO_LAUNCHER': '/tmp/x', 'HAO_LOGS': '/tmp/l', 'HAO_STICK': '/tmp/s', 'TMPDIR': '/tmp/t',
               'PATH': '/opt/evil/bin:/usr/bin', 'HAO_THEME': 'dark', 'SUDO_USER': 'u', 'SUDO_UID': '501'}
        gone = SAFE.harden_env(env, euid=0)
        self.assertEqual(sorted(gone), ['HAO_LAUNCHER', 'HAO_LOGS', 'HAO_STICK', 'TMPDIR'])
        self.assertEqual(env['PATH'], SAFE.SYSTEM_PATH)
        self.assertEqual(env['HAO_THEME'], 'dark')

    def test_sudo_home_comes_from_the_account_database(self):
        env = {'HOME': '/tmp/elsewhere', 'SUDO_USER': 'u', 'SUDO_UID': '501'}
        SAFE.harden_env(env, euid=0, home_of=lambda e: '/home-of-u')
        self.assertEqual(env['HOME'], '/home-of-u')

    def test_any_root_drops_them_but_the_recovery_keeps_its_drive(self):
        with tempfile.TemporaryDirectory() as d:
            here = Path(d) / 'hao' / 'tools' / 'hao' / 'src' / 'safety.py'
            env = {'HAO_STICK': d, 'HAO_LAUNCHER': '/tmp/x', 'HAO_LOGS': '/tmp/l', 'PATH': '/x'}
            self.assertEqual(sorted(SAFE.harden_env(env, euid=0, here=here)), ['HAO_LAUNCHER', 'HAO_LOGS'])
            self.assertEqual(env['HAO_STICK'], d)             # this hao runs from that drive: the launcher's
            self.assertEqual(env['PATH'], SAFE.SYSTEM_PATH)
            env = {'HAO_STICK': d}                             # a hao elsewhere: HAO_STICK is not the launcher's
            self.assertEqual(SAFE.harden_env(env, euid=0, here=Path('/usr/local/lib/hao/x.py')), ['HAO_STICK'])
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
        # a JSON escape decodes to a control character: cleaned after decoding too
        self.assertEqual(SAFE.clean({'unit': 'B\x1b[2J', 'n': [1, 'a\x07']}), {'unit': 'B\\x1b[2J', 'n': [1, 'a\\x07']})
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

    def test_a_folder_swapped_after_the_check_is_not_hashed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'root'
            root.mkdir()
            (Path(d) / 'outside').mkdir()
            (Path(d) / 'outside' / 'x').write_text('secret')
            (root / 'link').symlink_to(Path(d) / 'outside')
            self.assertEqual(VERIFY.hash_inside(root / 'link' / 'x', root), 'outside')
            (root / 'y').write_text('ok')
            self.assertEqual(len(VERIFY.hash_inside(root / 'y', root)), 64)


if __name__ == '__main__':
    unittest.main()
