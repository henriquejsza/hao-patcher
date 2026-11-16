from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(platform.system() == 'Darwin' and shutil.which('clang') and shutil.which('codesign'),
                     'native collector regression requires macOS and Xcode')
class ExactDependencyTests(unittest.TestCase):
    def test_recursive_constructor_matches_ordinary_runtime_identity(self):
        source=Path(__file__).with_name('swift-constructors.c')
        with tempfile.TemporaryDirectory(prefix='swift-constructors-') as tmp:
            binary=str(Path(tmp)/'test')
            subprocess.run(['clang','-arch','x86_64','-O2','-Wall','-Wextra','-Werror',str(source),'-o',binary],
                           check=True,capture_output=True)
            subprocess.run(['codesign','-s','-',binary],check=True,capture_output=True)
            result=subprocess.run([binary],text=True,capture_output=True,check=True,timeout=30)
            self.assertIn('canonical recursive constructor and failed dependency propagation: PASS',result.stdout)

    def test_lazy_metadata_is_initialized_before_parent(self):
        source = Path(__file__).with_name('swift-exact-dependencies.c')
        with tempfile.TemporaryDirectory(prefix='swift-exact-dependencies-') as tmp:
            binary = str(Path(tmp)/'test')
            subprocess.run(['clang', '-arch', 'x86_64', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(source), '-o', binary], check=True, capture_output=True)
            subprocess.run(['codesign', '-s', '-', binary], check=True, capture_output=True)
            result = subprocess.run([binary], check=True, capture_output=True, text=True, timeout=30)
            self.assertIn('PASS', result.stdout)
