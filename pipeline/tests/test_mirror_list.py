"""pipeline/mirror-list: what a release needs from a local mirror, one `SHA256 SIZE ORIGIN_URL NAME` line per file."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
TOOL = TOP / 'pipeline' / 'mirror-list'
M = runpy.run_path(str(TOOL))
R = runpy.run_path(str(TOP / 'pipeline' / 'release-cut'))
CLASSES = R['classes']()
IPSW = CLASSES['ipsw_27_0']


def h(c):
    return c * 64


class MirrorList(unittest.TestCase):
    def release(self, downloads):
        d = Path(tempfile.mkdtemp())
        p = d / 'release.json'
        p.write_text(json.dumps({'downloads': downloads, 'assets': [{'file': 'ours.tar', 'url': 'https://x/ours.tar',
                                                                     'size': 1, 'sha256': h('f')}]}))
        return p

    def run_tool(self, *args):
        return subprocess.run([sys.executable, '-I', str(TOOL), *map(str, args)], capture_output=True, text=True)

    def test_a_release_lists_downloads_and_streamed_files_sorted_once(self):
        p = self.release([
            {'row': 'kdk', 'name': 'kdk.dmg', 'url': 'https://e/kdk.dmg', 'size': 10, 'sha256': h('b')},
            {'row': 'ipsw_27_0', 'name': IPSW['name'], 'url': IPSW['url'], 'size': 30, 'sha256': IPSW['sha256'],
             'stream': 'ipsw', 'pins': {'members': {}}},
            {'row': 'tool', 'name': 'a tool.tar.gz', 'url': 'https://e/t.tgz', 'size': 20, 'sha256': h('a')},
            {'row': 'tool2', 'name': 'again.tar.gz', 'url': 'https://e/t.tgz', 'size': 20, 'sha256': h('a')}])
        r = self.run_tool(p)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertEqual(lines, sorted(lines))
        self.assertEqual(lines, ['%s 30 %s %s' % (IPSW['sha256'], IPSW['url'], IPSW['name']),
                                 '%s 20 https://e/t.tgz a%%20tool.tar.gz' % h('a'),
                                 '%s 10 https://e/kdk.dmg kdk.dmg' % h('b')])
        self.assertTrue(all(len(l.split(' ')) == 4 for l in lines))
        self.assertEqual(r.stderr, '')
        self.assertEqual(self.run_tool('--release', p).stdout, r.stdout)       # positional or --release

    def test_a_url_that_holds_another_file_is_not_printed(self):
        p = self.release([{'row': 'ipsw_27_0', 'name': 'UniversalMac_27.0_26A428_Restore.ipsw', 'url': IPSW['url'],
                           'size': 99, 'sha256': h('c'), 'stream': 'ipsw'}])
        r = self.run_tool(p)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, '%s 99 ? UniversalMac_27.0_26A428_Restore.ipsw\n' % h('c'))
        self.assertIn('origin unknown', r.stderr)
        self.assertIn(h('c'), r.stderr)

    def test_a_dry_cut_marks_a_row_from_another_build_unknown(self):
        d = Path(tempfile.mkdtemp())
        old = d / 'UniversalMac_27.0_26A428_Restore.ipsw'
        old.write_bytes(b'x' * 7)
        new = d / IPSW['name']
        new.write_bytes(b'y' * 5)
        for hit, want in (((d, (h('c'), str(old))), '%s 7 ? %s' % (h('c'), old.name)),
                          ((d, (IPSW['sha256'], str(new))), '%s 5 %s %s' % (IPSW['sha256'], IPSW['url'], IPSW['name']))):
            fake = dict(R, release_rows=lambda a, hit=hit: [('ipsw_27_0', hit), ('not_a_download', None)])
            rows, problems = M['from_assembly']('x.json', fake)
            self.assertEqual(problems, [])
            self.assertEqual(['%s %d %s %s' % (s, n, u or '?', name) for s, n, u, name in rows], [want])
        fake = dict(R, release_rows=lambda a: [('ipsw_27_0', (d, (IPSW['sha256'], str(d / 'gone'))))])
        self.assertIn('not here to size', M['from_assembly']('x.json', fake)[1][0])

    def test_release_cut_refuses_a_download_whose_url_holds_another_file(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(b'z'); f.close()
        self.addCleanup(os.unlink, f.name)
        item, problem = R['download_item']('ipsw_27_0', (None, (h('c'), f.name)), IPSW)
        self.assertIsNone(item)
        self.assertIn('url holds sha256 %s' % IPSW['sha256'], problem)
        item, problem = R['download_item']('ipsw_27_0', (None, (IPSW['sha256'], f.name)), IPSW)
        self.assertEqual((problem, item['size'], item['url']), (None, 1, IPSW['url']))

    def test_class_entries_name_a_valid_origin_sha256(self):
        for row, e in CLASSES.items():
            if 'sha256' in e:
                self.assertEqual(e['class'], 'download', row)
                self.assertRegex(e['sha256'], r'^[0-9a-f]{64}$', row)


if __name__ == '__main__':
    unittest.main()
