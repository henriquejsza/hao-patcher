"""programs.txt names exactly the libraries each listed program's edit specs insert, and the recipe that owns them."""
import json
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
