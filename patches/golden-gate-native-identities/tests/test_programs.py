"""programs.txt names exactly the libraries each listed program's edit specs insert, and the recipe that owns them."""
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]
TOP = HERE.parents[1]
sys.path.insert(0, str(HERE/'src'))
import native_identities as ni


def specs():
    for spec in sorted((TOP/'patches').glob('*/edits/*.json')):
        yield spec.parts[-3], json.loads(spec.read_text())


class ProgramsMatchTheEditSpecs(unittest.TestCase):
    def test_each_program_inserts_exactly_its_listed_libraries(self):
        for path, want in ni.load_programs().items():
            recipe, libs = want['recipe'], want['libs']
            inserted, owners = set(), set()
            for name, spec in specs():
                if spec.get('path') != path:
                    continue
                owners.add(name)
                inserted |= {e['args']['path'] for e in spec.get('edits', [])
                             if e.get('kind') == 'op' and e.get('op') == 'macho.add-dylib'}
            self.assertIn(recipe, owners, f'{path}: no edit spec of {recipe} edits it')
            self.assertEqual(inserted, set(libs), path)

    def test_every_signed_executable_edit_is_listed(self):
        # an Apple or Tahoe program (a path whose last part has no extension, outside usr/lib) that a spec re-signs
        found = {spec['path'] for _, spec in specs()
                 if spec.get('sign') and spec.get('origin', {}).get('kind') in ('apple', 'tahoe')
                 and '.' not in spec['path'].rsplit('/', 1)[-1] and not spec['path'].startswith('usr/lib/')}
        self.assertEqual(found, set(ni.load_programs()))

    def test_every_resigned_program_with_a_listed_path_is_known(self):
        listed = ni.load_programs()
        for name, spec in specs():
            if spec.get('path') in listed and spec.get('sign'):
                self.assertEqual(listed[spec['path']]['recipe'], name, spec['path'])


if __name__ == '__main__':
    unittest.main()


class Slack(unittest.TestCase):
    """The bytes after the SuperBlob: zeros or the original's own, never free; their length is the signer's."""
    def test_exactly_the_originals_bytes_then_zeros_pass(self):
        reference = bytes(range(1, 256)) * 4
        start = 100
        slack = reference[start:] + bytes(3000)                                      # longer than the original
        self.assertIsNone(ni.slack_problem({'slack': (start, slack)}, reference))

    def test_any_other_byte_is_refused(self):
        reference = bytes(range(1, 256)) * 4
        self.assertIn('not the original', ni.slack_problem({'slack': (10, reference[10:12] + b'\x41')}, reference))
        self.assertIn('not the original', ni.slack_problem({'slack': (len(reference) - 1, reference[-1:] + b'\x41')},
                                                            reference))               # past the original: zero only

    def test_selective_zeroing_is_refused(self):
        reference = bytes(range(1, 256)) * 4
        slack = bytearray(reference[100:200]); slack[7] = 0                         # one original byte zeroed
        self.assertIn('not the original', ni.slack_problem({'slack': (100, bytes(slack))}, reference))

    def test_policy_no_longer_depends_on_the_slack(self):
        import inspect
        source = inspect.getsource(ni.signature_profile)
        self.assertNotIn("b'\\0slack\\0'", source)


@unittest.skipUnless(os.environ.get('NATIVE_IDENTITIES_SIGNED') and os.environ.get('NATIVE_IDENTITIES_ORIGINALS'),
                     'set NATIVE_IDENTITIES_SIGNED (a folder with signed/ and vm-signed/ copies of each program, by name) '
                     'and NATIVE_IDENTITIES_ORIGINALS=DIR:DIR (folders holding the originals at their system paths)')
class RealSigners(unittest.TestCase):
    """The same program signed on the host and in the builder VM: one policy, slack accepted against the original."""
    def test_host_and_vm_agree(self):
        pins = Path(os.environ['NATIVE_IDENTITIES_SIGNED'])
        programs = ni.load_programs()
        roots = [Path(r) for r in os.environ['NATIVE_IDENTITIES_ORIGINALS'].split(':')]
        for rel in programs:
            name = rel.rsplit('/', 1)[1]
            original = next(r/rel for r in roots if (r/rel).is_file() and ni.x86_64(str(r/rel))[1] is not None)
            reference = ni.x86_64(str(original))[1]
            policies = set()
            for kind in ('signed', 'vm-signed'):
                profile = ni.signature_profile(ni.x86_64(str(pins/kind/name))[1])
                self.assertIsNone(ni.slack_problem(profile, reference), (name, kind))
                policies.add(profile['policy'])
            self.assertEqual(len(policies), 1, name)
            self.assertIn(policies.pop(), {b[3] for b in programs[rel]['builds']}, name)
