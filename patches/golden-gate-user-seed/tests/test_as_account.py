"""seed.zsh writes into an account's folders only as that account: the *_as functions run through asuser
(`sudo -u #uid zsh`), root-side functions write nowhere but root's own folders. Runs the real asuser path with a
`sudo` stub that runs the command as the current user, on fixture folders."""
import os
import re
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SCRIPT = (HERE / 'src/seed.zsh').read_text()
WRITES = re.compile(r'(?<![\w-])(cp |zf_mv|zf_mkdir|zf_chmod|zf_chown|sqlite3)')
ROOT_WRITERS = {'place_wp'}   # /private/var/db/Wallpapers: root's folder, made root:wheel


def functions():
    """name -> body text of each function defined at column 0."""
    out, lines, i = {}, SCRIPT.splitlines(), 0
    while i < len(lines):
        m = re.match(r'([a-z_]+)\(\) *\{', lines[i])
        if not m:
            i += 1
            continue
        if lines[i].count('{') == lines[i].count('}'):   # a one-line function (maybe with a comment)
            out[m.group(1)] = lines[i]
            i += 1
            continue
        j = i + 1
        while lines[j] != '}':
            j += 1
        out[m.group(1)] = '\n'.join(lines[i:j + 1])
        i = j + 1
    return out


FN = functions()


class Static(unittest.TestCase):
    def test_root_side_functions_do_not_write(self):
        for name, body in FN.items():
            if name.endswith('_as') or name in ROOT_WRITERS:
                continue
            body = re.sub(r'^[a-z_]+\(\) *\{', '', body)
            code = '\n'.join(line.split('#')[0] for line in body.splitlines() if 'zmodload' not in line)
            self.assertIsNone(WRITES.search(code), '%s writes as root: %s' % (name, WRITES.search(code)))

    def test_every_account_function_is_shipped_to_the_child(self):
        asfns = re.search(r'^ASFNS=\(([^)]*)\)', SCRIPT, re.M).group(1).split()
        self.assertEqual(sorted(n for n in FN if n.endswith('_as')), sorted(n for n in asfns if n.endswith('_as')))
        for n in asfns:
            self.assertIn(n, FN)

    def test_poke_runs_as_the_account(self):
        self.assertIn('launchctl asuser $uid $SUDO -n -u "#$uid" -- "$POKE"', SCRIPT)
        self.assertIn('\nSUDO=/usr/bin/sudo\n', SCRIPT)


@unittest.skipUnless(os.getuid() >= 501, 'asuser refuses uids below 501')
class AsAccount(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = Path(self.tmp.name)
        shims = d / 'shims'
        shims.mkdir()
        # sudo -u #UID -- CMD...: run CMD as this user, and record that it went through sudo
        (shims / 'sudo').write_text('#!/bin/sh\n[ "$1 $2" = "-n -u" ] && [ "$4" = -- ] || exit 9\n'
                                    'echo "$3" >> "%s"\nshift 4\nexec "$@"\n' % (d / 'sudo.log'))
        (shims / 'sudo').chmod(0o755)
        self.seed = d / 'seed'
        (self.seed / 'is').mkdir(parents=True)
        for n in ('store.index', '__cache_info__'):
            (self.seed / 'is' / n).write_text(n)
        (self.seed / 'ls').mkdir()
        (self.seed / 'ls/com.apple.LaunchServices-20971545-v2.csstore').write_text('ls')
        for tree, files in {'com.apple.dock.extra': ['a/b'], 'com.apple.Spotlight': ['c'],
                            'com.apple.Safari': ['com.apple.metalfe/x.pcm', 'd']}.items():
            for f in files:
                p = self.seed / 'metal' / tree / f
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(f)
        (self.seed / 'fonts').mkdir()
        db = sqlite3.connect(self.seed / 'fonts/fontregistry.user')
        db.execute('CREATE TABLE dir_table (domain_column INTEGER, path_column TEXT)')
        db.execute("INSERT INTO dir_table VALUES (1, '/var/empty/Library/Fonts')")
        db.commit()
        db.close()
        self.C = d / 'C'
        self.D = d / 'D'
        self.C.mkdir()
        self.D.mkdir()
        self.env = dict(os.environ, PATH='%s:/usr/bin:/bin:/usr/sbin:/sbin' % shims)

    def tearDown(self):
        self.tmp.cleanup()

    def run_zsh(self, body):
        defs = '\n'.join(FN[n] for n in FN)
        head = re.search(r'^ASFNS=.*$', SCRIPT, re.M).group(0)
        text = '\n'.join([
            'zmodload zsh/datetime; zmodload -F zsh/files b:zf_mv b:zf_rm b:zf_mkdir b:zf_chown b:zf_chmod;'
            ' zmodload -F zsh/stat b:zstat; zmodload zsh/zselect',
            'SEED=%s LSN=com.apple.LaunchServices-20971545-v2.csstore BMSRC= FONTPH=/var/empty/Library/Fonts' % self.seed,
            'SUDO=%s' % (self.d / 'shims/sudo'),
            head, defs, body])
        r = subprocess.run(['/bin/zsh', '-f', '-c', text], capture_output=True, text=True, env=self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_icon_ls_fonts_and_metal_go_through_sudo_and_land(self):
        uid, name = os.getuid(), os.environ.get('USER') or subprocess.run(['id', '-un'], capture_output=True,
                                                                          text=True).stdout.strip()
        (self.C / 'com.apple.Spotlight').mkdir()   # the app made its own tree first: kept
        r = self.run_zsh('\n'.join([
            'asuser %d is_place_as %s %s/ || exit 3' % (uid, name, self.C),
            'asuser %d ls_stage_as %s %s/ && asuser %d ls_swap_as %s %s/ || exit 4' % (uid, name, self.D, uid, name, self.D),
            'place_fonts %s %d 20 %s/' % (name, uid, self.C),
            'NB=0 NS=0 KEPT=(); place_chunk %s %d 20 %s/ $EPOCHREALTIME com.apple.dock.extra com.apple.Spotlight '
            'com.apple.Safari || exit 5' % (name, uid, self.C),
            'print -r -- "RESULT $NB $NS ${KEPT[*]}"']))
        self.assertIn('RESULT 2 1 com.apple.Spotlight', r.stdout)
        self.assertEqual((self.C / 'com.apple.iconservices/store.index').read_text(), 'store.index')
        self.assertEqual(oct((self.C / 'com.apple.iconservices').stat().st_mode & 0o777), '0o711')
        self.assertEqual((self.D / 'com.apple.LaunchServices.dv/com.apple.LaunchServices-20971545-v2.csstore')
                         .read_text(), 'ls')
        self.assertEqual((self.C / 'com.apple.dock.extra/a/b').read_text(), 'a/b')
        self.assertTrue((self.C / 'com.apple.Safari/d').is_file())
        self.assertFalse((self.C / 'com.apple.Safari/com.apple.metalfe').exists())
        self.assertFalse((self.C / '.peruser-seed.stage').exists())
        reg = sqlite3.connect(self.C / 'com.apple.FontRegistry/fontregistry.user')
        self.assertTrue(reg.execute('SELECT path_column FROM dir_table').fetchone()[0].endswith('/Library/Fonts'))
        reg.close()
        self.assertEqual(set((self.d / 'sudo.log').read_text().split()), {'#%d' % uid})
        self.assertEqual(len((self.d / 'sudo.log').read_text().split()), 5)

    def test_a_forged_chunk_answer_is_refused(self):
        uid = os.getuid()
        r = self.run_zsh('\n'.join([
            'chunk_place_as() { print -u3 -r -- "1 0 x=5" }; ASFNS+=(chunk_place_as)',
            'NB=0 NS=0 KEPT=(); place_chunk u %d 20 %s/ 0 com.apple.dock.extra && exit 6' % (uid, self.C),
            'chunk_place_as() { print -u3 -r -- "0 1 /etc" }',
            'place_chunk u %d 20 %s/ 0 com.apple.dock.extra && exit 7' % (uid, self.C),
            'print -r -- "RESULT $NB $NS ${KEPT[*]}"']))
        self.assertIn('RESULT 0 0 ', r.stdout)
        self.assertIn('bad answer', r.stdout)
        self.assertIn('unknown tree /etc', r.stdout)

    def test_refuses_system_uids(self):
        r = self.run_zsh('asuser 0 is_place_as root %s/ && exit 7; exit 0' % self.C)
        self.assertIn("refused uid '0'", r.stdout)
        self.assertFalse((self.C / 'com.apple.iconservices').exists())


if __name__ == '__main__':
    unittest.main()
