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
        for path, (recipe, libs) in ni.load_programs().items():
            inserted, owners = set(), set()
            for name, spec in specs():
                if spec.get('path') != path:
                    continue
                owners.add(name)
                inserted |= {e['args']['path'] for e in spec.get('edits', [])
                             if e.get('kind') == 'op' and e.get('op') == 'macho.add-dylib'}
            self.assertIn(recipe, owners, f'{path}: no edit spec of {recipe} edits it')
            self.assertEqual(inserted, set(libs), path)

    def test_every_resigned_program_with_a_listed_path_is_known(self):
        listed = ni.load_programs()
        for name, spec in specs():
            if spec.get('path') in listed and spec.get('sign'):
                self.assertEqual(listed[spec['path']][0], name, spec['path'])


if __name__ == '__main__':
    unittest.main()
