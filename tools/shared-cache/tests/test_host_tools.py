"""host_tools: the toolchain's architecture comes from what toolchain/make built (arm64 or x86_64)."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.host_tools import BUILDER_OBJECTS, builder_objects, toolchain_arch


class ToolchainArch(unittest.TestCase):
    def toolchain(self, *arches):
        base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for arch in arches:
            (base / BUILDER_OBJECTS / 'Objects-normal' / arch).mkdir(parents=True)
        return base

    def test_the_one_built_architecture(self):
        for arch in ('arm64', 'x86_64'):
            base = self.toolchain(arch)
            self.assertEqual(arch, toolchain_arch(base))
            self.assertEqual(base / BUILDER_OBJECTS / 'Objects-normal' / arch, builder_objects(base))

    def test_none_or_two_is_refused(self):
        for arches in ((), ('arm64', 'x86_64')):
            with self.assertRaisesRegex(RuntimeError, 'expected one architecture'):
                toolchain_arch(self.toolchain(*arches))


if __name__ == '__main__':
    unittest.main()
