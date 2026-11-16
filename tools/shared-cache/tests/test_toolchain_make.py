"""toolchain/make: dyld's VersionMap.h is generated only from AvailabilityVersions-157.2's own files."""
from importlib.machinery import SourceFileLoader
import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'toolchain/make'
LOADER = SourceFileLoader('toolchain_make', str(PATH))
SPEC = importlib.util.spec_from_loader('toolchain_make', LOADER)
MAKE = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(MAKE)


class VersionMap(unittest.TestCase):
    def test_pins_name_the_three_files_used(self):
        self.assertEqual({'availability', 'availability.dsl', 'templates/VersionMap.h'}, set(MAKE.AVAILABILITY_FILES))
        self.assertTrue(all(len(h) == 64 for h in MAKE.AVAILABILITY_FILES.values()))

    def test_a_different_copy_is_refused_before_anything_runs(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / 'availability-versions'
            (source / 'templates').mkdir(parents=True)
            for name in MAKE.AVAILABILITY_FILES:
                (source / name).write_text('not the pinned file\n')
            destination = Path(scratch) / 'tree/include/dyld/VersionMap.h'
            with self.assertRaisesRegex(SystemExit, 'sha256 differs'):
                MAKE.version_map(source, Path(scratch), destination)
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
