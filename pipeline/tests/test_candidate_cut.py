"""pipeline/candidate-cut with fake steps: the release stick and the dev stick, and create-installer's phase times."""
from pathlib import Path
import json
import runpy
import shutil
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
C = runpy.run_path(str(TOP / 'pipeline' / 'candidate-cut'))


class Cut(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.root = Path(self.d.name).resolve()
        (self.root / 'store').mkdir()
        self.calls = []

    def tearDown(self):
        self.d.cleanup()

    def fake_checkout(self, dev=True):
        def make(sha, tree):
            (tree / 'pipeline/assemblies').mkdir(parents=True)
            (tree / 'tools/hao/data').mkdir(parents=True)
            (tree / 'pipeline/release-cut').write_text("--candidate\n" + ("'--dev'\n" if dev else ''))
            for name in ('mbp92-26B131-alpha-v0.1.0', 'dev-26B131-alpha-v0.1.0'):
                (tree / 'pipeline/assemblies' / (name + '.json')).write_text('{}')
        return make, lambda tree: None

    def fake_run(self, cmd, cwd, log, env):
        cmd = [str(c) for c in cmd]
        self.calls.append((cmd, env['HAO_LOGS']))
        log.write_text('ran\n')
        if 'pipeline/release-cut' in cmd:
            out = Path(cmd[cmd.index('--write') + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps({'candidate': True, **({'dev': True} if '--dev' in cmd else {}),
                                       'assembly': Path(cmd[cmd.index('--write') + 2]).stem}))
        if 'create-installer' in cmd:
            Path(cmd[cmd.index('--image') + 1]).write_bytes(b'stick for ' + cmd[cmd.index('--release') + 1].encode())
        return 0

    def cut(self, *extra, dev=True):
        out = self.root / 'out'
        rc = C['main'](['HEAD', '--out', str(out)] + list(extra), store=self.root / 'store', run=self.fake_run,
                       worktree=self.fake_checkout(dev))
        return rc, json.loads((out / 'candidate.json').read_text()), out

    def test_both_sticks_are_made_and_listed(self):
        rc, rec, out = self.cut()
        self.assertEqual(rc, 0)
        self.assertTrue(rec['passed'])
        self.assertEqual([s['kind'] for s in rec['sticks']], ['release', 'dev'])
        rel, dev = rec['sticks']
        self.assertEqual(rel['path'], str(out / 'stick.img'))
        self.assertEqual(dev['path'], str(out / 'dev' / 'stick.img'))
        for s in rec['sticks']:
            self.assertEqual(s['sha256'], C['sha256'](s['path']))
            self.assertEqual(s['size'], Path(s['path']).stat().st_size)
        self.assertTrue((out / 'dev' / 'stick.img.sha256').read_text().startswith(dev['sha256']))
        self.assertEqual(rec['dev']['image_sha256'], dev['sha256'])
        self.assertTrue(rec['dev']['passed'])
        cuts = [c for c, _ in self.calls if 'pipeline/release-cut' in c]
        self.assertEqual(len(cuts), 2)
        self.assertIn('--dev', cuts[1])
        self.assertIn('pipeline/assemblies/dev-26B131-alpha-v0.1.0.json', cuts[1])
        self.assertTrue(json.loads((out / 'dev/release/release.json').read_text())['dev'])
        self.assertEqual({e for c, e in self.calls if 'create-installer' in c},
                         {str(out / 'logs'), str(out / 'dev' / 'logs')})

    def test_the_release_stick_is_unchanged_by_the_dev_stick(self):
        rc, with_dev, out = self.cut()
        release_calls = [c for c, logs in self.calls if logs == str(out / 'logs')]
        self.calls = []
        shutil.rmtree(out)
        rc, without, out = self.cut('--no-dev')
        self.assertEqual(without['dev'], {'skipped': '--no-dev'})
        self.assertEqual([s['kind'] for s in without['sticks']], ['release'])
        self.assertEqual(without['sticks'][0], with_dev['sticks'][0])
        self.assertEqual([c for c, _ in self.calls], release_calls)
        self.assertNotIn('--dev', [x for c, _ in self.calls for x in c])
        self.assertFalse('dev' in json.loads((out / 'release/release.json').read_text()))

    def test_a_commit_without_the_dev_cut_is_recorded_as_skipped(self):
        rc, rec, out = self.cut(dev=False)
        self.assertEqual(rc, 0)
        self.assertIn('--dev', rec['dev']['skipped'])
        self.assertEqual(len(rec['sticks']), 1)

    def test_a_failed_dev_step_fails_the_cut(self):
        real = self.fake_run

        def run(cmd, cwd, log, env):
            return 1 if 'create-installer' in [str(c) for c in cmd] and '/dev/' in str(log) else real(cmd, cwd, log, env)
        self.fake_run = run
        rc, rec, out = self.cut()
        self.assertEqual(rc, 1)
        self.assertFalse(rec['passed'])
        self.assertFalse(rec['dev']['passed'])
        self.assertEqual(rec['dev']['steps'][-1]['name'], 'create-installer-dev')


class Phases(unittest.TestCase):
    def test_phases_from_the_event_log(self):
        events = [dict(ev='run.start', t=3.0), dict(ev='step.start', t=10.0, step='Download'),
                  dict(ev='command', t=12.0, argv=['py', '-I', '/x/pipeline/place']),
                  dict(ev='command', t=14.0, argv=['py', '-I', '/x/pipeline/make-on-mac']),
                  dict(ev='task.start', t=50.0, text='  stage   inputs'), dict(ev='task.end', t=90.0),
                  dict(ev='run.end', t=95.0)]
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(C['phases'](d))
            (Path(d) / 'create-installer-1.json').write_text(json.dumps({'events': events}))
            self.assertEqual(C['phases'](d), [['doctor and questions', 10.0], ['step: Download', 2.0],
                                              ['place', 2.0], ['make-on-mac', 36.0], ['stage inputs', 40.0]])


if __name__ == '__main__':
    unittest.main()
