"""patch.json "files" declares what apply.sh installs: every declared path is installed by apply.sh from the row or
src file the declaration names, and apply.sh installs nothing else.
python3.14 -I -B -m unittest discover -s patches/dev-access/tests"""
import json
import plistlib
from pathlib import Path
import re
import unittest

PATCH = Path(__file__).resolve().parents[1]
PJ = json.loads((PATCH / 'patch.json').read_text())
APPLY = (PATCH / 'apply.sh').read_text()
SOURCES = {'private/var/root/.testssh/sshd_config': '$P/src/sshd_config',
           'Library/LaunchDaemons/local.testssh.plist': '$P/src/local.testssh.plist',
           'Library/LaunchDaemons/dev.hao.screensharing.plist': '$P/src/dev.hao.screensharing.plist'}


class Declaration(unittest.TestCase):
    def test_every_installed_file_is_declared_from_its_source(self):
        installs = {}
        for m in re.finditer(r'^install -o root -g wheel -m \d+ (\S+) (\S+)$', APPLY, re.M):
            dest = m.group(2).replace('$T', '$DATA/private/var/root/.testssh')
            self.assertTrue(dest.startswith('$DATA/'), dest)
            installs[dest[len('$DATA/'):]] = m.group(1)
        declared = {f['path']: f['origin'] for f in PJ['files']}
        self.assertEqual(set(installs), set(declared))
        for path, source in installs.items():
            origin = declared[path]
            self.assertEqual(origin['kind'], 'hao')
            if 'row' in origin:
                self.assertEqual(source, '$P/inputs/' + origin['row'])
                self.assertIn(origin['row'], PJ['inputs'])
            else:
                self.assertEqual(source, SOURCES[path])
                self.assertTrue((PATCH / source.replace('$P/', '')).is_file())
        self.assertEqual({o['row'] for o in declared.values() if 'row' in o}, set(PJ['inputs']))


class ScreenSharing(unittest.TestCase):
    def test_a_system_job_at_every_boot_for_the_listed_accounts(self):
        job = plistlib.loads((PATCH / 'src/dev.hao.screensharing.plist').read_bytes())
        self.assertEqual(job['Label'], 'dev.hao.screensharing')
        self.assertTrue(job['RunAtLoad'])
        for key in ('LimitLoadToSessionType', 'UserName', 'KeepAlive'):
            self.assertNotIn(key, job)          # system domain, once per boot: before Setup Assistant and any login
        script = job['ProgramArguments'][2]
        self.assertEqual(job['ProgramArguments'][:2], ['/bin/sh', '-c'])
        self.assertIn('for u in $(/bin/cat $U)', script)
        self.assertIn('-append $G GroupMembership $u', script)   # by name: works before the account exists
        self.assertIn('U=/private/var/root/.testssh/screensharing-users', script)
        self.assertIn('G=/Groups/com.apple.access_screensharing', script)
        self.assertIn('launchctl enable system/com.apple.screensharing', script)
        self.assertIn('launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.screensharing.plist', script)
        self.assertNotIn('kickstart', script)   # ARD's kickstart needs an arm64e-only Perl bridge; plain Screen Sharing


if __name__ == '__main__':
    unittest.main()
